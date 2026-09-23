/**
 * Copyright (c) HashiCorp, Inc.
 * SPDX-License-Identifier: MPL-2.0
 */

import { module, test } from 'qunit';
import { setupTest } from 'ember-qunit';
import sinon from 'sinon';

module('Unit | Adapter | cluster', function (hooks) {
  setupTest(hooks);

  hooks.beforeEach(function () {
    this.adapter = this.owner.lookup('adapter:cluster');
  });

  test('it posts only the role for kerberos, to the type or the mount path', async function (assert) {
    const ajax = sinon.stub(this.adapter, 'ajax').resolves({});

    await this.adapter.authenticate({ backend: 'kerberos', data: {} });
    assert.deepEqual(ajax.lastCall.args, [
      '/v1/auth/kerberos/login',
      'POST',
      { unauthenticated: true, data: {} },
    ]);

    await this.adapter.authenticate({ backend: 'kerberos', data: { role: 'hadoop', path: 'kerb' } });
    assert.deepEqual(ajax.lastCall.args, [
      '/v1/auth/kerb/login',
      'POST',
      { unauthenticated: true, data: { role: 'hadoop' } },
    ]);
  });
});
