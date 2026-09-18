const jwt = require('../index');
const crypto = require('crypto');
const assert = require('chai').assert;
const expect = require('chai').expect;
const JsonWebTokenError = require('../lib/JsonWebTokenError');

describe('issue 1046', function () {
  it('verifies HS256 tokens signed with a string secret', function () {
    const secret = 'a-shared-secret-of-reasonable-length';
    const token = jwt.sign({ sub: 'u' }, secret, { algorithm: 'HS256' });
    const decoded = jwt.verify(token, secret, { algorithms: ['HS256'] });
    assert.equal(decoded.sub, 'u');
  });

  it('still rejects HMAC verification with a PEM public key', function () {
    const { publicKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    const pem = publicKey.export({ type: 'spki', format: 'pem' });
    const maliciousToken = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6InJzYUtleUlkIn0.eyJmb28iOiJiYXIiLCJpYXQiOjE2NTk1MTA2MDh9.cOcHI1TXPbxTMlyVTfjArSWskrmezbrG8iR7uJHwtrQ';

    expect(() => jwt.verify(maliciousToken, pem, { algorithms: ['RS256', 'HS256'] }))
      .to.throw(JsonWebTokenError, 'must be a symmetric key');
  });
});
