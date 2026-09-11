// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package kerberos

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"
	"unicode/utf8"
)

// The encodings below are byte-compatible with Hadoop's
// AbstractDelegationTokenIdentifier, Token and WritableUtils, so a token
// issued here can be carried by the Hadoop Token/Credentials machinery and
// decoded by a TokenIdentifier subclass on the client side.

const (
	// identifierVersion is the leading version byte of Hadoop 3 identifiers.
	identifierVersion byte = 0

	// maxTextLength bounds a single Text field (Hadoop Text.DEFAULT_MAX_LEN).
	maxTextLength = 1024 * 1024
)

// delegationTokenIdentifier is the public part of a delegation token.
// Dates are milliseconds since the Unix epoch, as in Hadoop.
type delegationTokenIdentifier struct {
	Owner          string
	Renewer        string
	RealUser       string
	IssueDate      int64
	MaxDate        int64
	SequenceNumber int32
	MasterKeyID    int32
}

func (id *delegationTokenIdentifier) marshal() []byte {
	var buf bytes.Buffer
	buf.WriteByte(identifierVersion)
	writeText(&buf, id.Owner)
	writeText(&buf, id.Renewer)
	writeText(&buf, id.RealUser)
	writeVLong(&buf, id.IssueDate)
	writeVLong(&buf, id.MaxDate)
	writeVLong(&buf, int64(id.SequenceNumber))
	writeVLong(&buf, int64(id.MasterKeyID))
	return buf.Bytes()
}

// unmarshalIdentifier parses an identifier strictly: the version byte must
// match, the owner must be set and no bytes may follow the last field.
func unmarshalIdentifier(data []byte) (*delegationTokenIdentifier, error) {
	r := bytes.NewReader(data)
	version, err := r.ReadByte()
	if err != nil {
		return nil, errors.New("empty token identifier")
	}
	if version != identifierVersion {
		return nil, fmt.Errorf("unknown token identifier version %d", version)
	}

	id := &delegationTokenIdentifier{}
	if id.Owner, err = readText(r); err != nil {
		return nil, err
	}
	if id.Renewer, err = readText(r); err != nil {
		return nil, err
	}
	if id.RealUser, err = readText(r); err != nil {
		return nil, err
	}
	if id.IssueDate, err = readVLong(r); err != nil {
		return nil, err
	}
	if id.MaxDate, err = readVLong(r); err != nil {
		return nil, err
	}
	if id.SequenceNumber, err = readVInt(r); err != nil {
		return nil, err
	}
	if id.MasterKeyID, err = readVInt(r); err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing bytes after token identifier")
	}
	if id.Owner == "" {
		return nil, errors.New("token identifier has empty owner")
	}
	return id, nil
}

// delegationToken is the wire form of Hadoop's Token: identifier, password,
// kind and service.
type delegationToken struct {
	Identifier []byte
	Password   []byte
	Kind       string
	Service    string
}

func (t *delegationToken) marshal() []byte {
	var buf bytes.Buffer
	writeVLong(&buf, int64(len(t.Identifier)))
	buf.Write(t.Identifier)
	writeVLong(&buf, int64(len(t.Password)))
	buf.Write(t.Password)
	writeText(&buf, t.Kind)
	writeText(&buf, t.Service)
	return buf.Bytes()
}

func unmarshalToken(data []byte) (*delegationToken, error) {
	r := bytes.NewReader(data)
	t := &delegationToken{}
	var err error
	if t.Identifier, err = readBytes(r); err != nil {
		return nil, err
	}
	if t.Password, err = readBytes(r); err != nil {
		return nil, err
	}
	if t.Kind, err = readText(r); err != nil {
		return nil, err
	}
	if t.Service, err = readText(r); err != nil {
		return nil, err
	}
	if r.Len() != 0 {
		return nil, errors.New("trailing bytes after token")
	}
	return t, nil
}

// encodeURLString matches Token.encodeToUrlString: URL-safe base64 without
// padding.
func (t *delegationToken) encodeURLString() string {
	return base64.RawURLEncoding.EncodeToString(t.marshal())
}

// decodeURLString accepts the output of Token.encodeToUrlString and, like
// the commons-codec decoder behind Token.decodeFromUrlString, tolerates the
// standard alphabet and padding.
func decodeURLString(s string) (*delegationToken, error) {
	s = strings.TrimRight(strings.TrimSpace(s), "=")
	s = strings.NewReplacer("+", "-", "/", "_").Replace(s)
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("token is not base64: %w", err)
	}
	return unmarshalToken(raw)
}

func writeText(buf *bytes.Buffer, s string) {
	writeVLong(buf, int64(len(s)))
	buf.WriteString(s)
}

func readText(r *bytes.Reader) (string, error) {
	raw, err := readBytes(r)
	if err != nil {
		return "", err
	}
	if !utf8.Valid(raw) {
		return "", errors.New("text field is not valid UTF-8")
	}
	return string(raw), nil
}

// readBytes reads a vint length prefix followed by that many bytes.
func readBytes(r *bytes.Reader) ([]byte, error) {
	n, err := readVInt(r)
	if err != nil {
		return nil, err
	}
	if n < 0 || n > maxTextLength {
		return nil, fmt.Errorf("invalid field length %d", n)
	}
	if int(n) > r.Len() {
		return nil, io.ErrUnexpectedEOF
	}
	raw := make([]byte, n)
	if _, err := io.ReadFull(r, raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// writeVLong follows WritableUtils.writeVLong: one byte for [-112, 127],
// otherwise a prefix byte carrying the sign and byte count followed by the
// magnitude in big-endian order.
func writeVLong(buf *bytes.Buffer, v int64) {
	if v >= -112 && v <= 127 {
		buf.WriteByte(byte(v))
		return
	}
	prefix := int64(-112)
	if v < 0 {
		v = ^v
		prefix = -120
	}
	for tmp := v; tmp != 0; tmp >>= 8 {
		prefix--
	}
	buf.WriteByte(byte(prefix))
	n := -(prefix + 112)
	if prefix < -120 {
		n = -(prefix + 120)
	}
	for idx := n; idx != 0; idx-- {
		shift := uint((idx - 1) * 8)
		buf.WriteByte(byte(v >> shift))
	}
}

func readVLong(r *bytes.Reader) (int64, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, io.ErrUnexpectedEOF
	}
	first := int8(b)
	n := vintSize(first)
	if n == 1 {
		return int64(first), nil
	}
	var v int64
	for i := 0; i < n-1; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return 0, io.ErrUnexpectedEOF
		}
		v = v<<8 | int64(b)
	}
	if first < -120 || (first >= -112 && first < 0) {
		v = ^v
	}
	return v, nil
}

func readVInt(r *bytes.Reader) (int32, error) {
	v, err := readVLong(r)
	if err != nil {
		return 0, err
	}
	if v < math.MinInt32 || v > math.MaxInt32 {
		return 0, fmt.Errorf("value %d does not fit an int", v)
	}
	return int32(v), nil
}

// vintSize mirrors WritableUtils.decodeVIntSize.
func vintSize(first int8) int {
	switch {
	case first >= -112:
		return 1
	case first < -120:
		return int(-119 - int(first))
	default:
		return int(-111 - int(first))
	}
}
