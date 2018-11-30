"use strict";
/**
 * Copyright 2018 Google LLC
 *
 * Distributed under MIT license.
 * See file LICENSE for detail or copy at https://opensource.org/licenses/MIT
 */
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : new P(function (resolve) { resolve(result.value); }).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert = require("assert");
const fs = require("fs");
const nock = require("nock");
const src_1 = require("../src");
const EMAIL = 'example@developer.gserviceaccount.com';
const UNKNOWN_KEYFILE = './test/assets/key';
const KEYFILE = './test/assets/key.pem';
const P12FILE = './test/assets/key.p12';
const KEYFILEJSON = './test/assets/key.json';
const KEYFILENOEMAILJSON = './test/assets/key-no-email.json';
const KEYCONTENTS = fs.readFileSync(KEYFILE, 'utf8');
const KEYJSONCONTENTS = fs.readFileSync(KEYFILEJSON, 'utf8');
const GOOGLE_TOKEN_URLS = ['https://www.googleapis.com', '/oauth2/v4/token'];
const GOOGLE_REVOKE_TOKEN_URLS = ['https://accounts.google.com', '/o/oauth2/revoke', '?token='];
const TESTDATA = {
    email: 'email@developer.gserviceaccount.com',
    scope: 'scope123',
    key: KEYCONTENTS
};
const TESTDATA_KEYFILE = {
    email: 'email@developer.gserviceaccount.com',
    sub: 'developer@gmail.com',
    scope: 'scope123',
    keyFile: KEYFILE
};
const TESTDATA_UNKNOWN = {
    keyFile: UNKNOWN_KEYFILE
};
const TESTDATA_KEYFILENOEMAIL = {
    scope: 'scope123',
    keyFile: KEYFILE
};
const TESTDATA_KEYFILEJSON = {
    scope: 'scope123',
    keyFile: KEYFILEJSON
};
const TESTDATA_KEYFILENOEMAILJSON = {
    scope: 'scope123',
    keyFile: KEYFILENOEMAILJSON
};
const TESTDATA_P12 = {
    email: 'email@developer.gserviceaccount.com',
    scope: 'scope123',
    keyFile: P12FILE
};
const TESTDATA_P12_NO_EMAIL = {
    scope: 'scope123',
    keyFile: P12FILE
};
nock.disableNetConnect();
it('should exist', () => {
    assert.strictEqual(typeof src_1.GoogleToken, 'function');
});
it('should work without new or options', () => {
    const gtoken = new src_1.GoogleToken();
    assert(gtoken);
});
describe('.iss', () => {
    it('should be set from email option', () => {
        const gtoken = new src_1.GoogleToken({ email: EMAIL });
        assert.strictEqual(gtoken.iss, EMAIL);
        assert.strictEqual(gtoken.email, undefined);
    });
    it('should be set from iss option', () => {
        const gtoken = new src_1.GoogleToken({ iss: EMAIL });
        assert.strictEqual(gtoken.iss, EMAIL);
    });
    it('should be set from sub option', () => {
        const gtoken = new src_1.GoogleToken({ sub: EMAIL });
        assert.strictEqual(gtoken.sub, EMAIL);
    });
    it('should be set from email option over iss option', () => {
        const gtoken = new src_1.GoogleToken({ iss: EMAIL, email: 'another' + EMAIL });
        assert.strictEqual(gtoken.iss, 'another' + EMAIL);
    });
});
describe('.scope', () => {
    it('should accept strings', () => {
        const gtoken = new src_1.GoogleToken({ scope: 'hello world' });
        assert.strictEqual(gtoken.scope, 'hello world');
    });
    it('should accept array of strings', () => {
        const gtoken = new src_1.GoogleToken({ scope: ['hello', 'world'] });
        assert.strictEqual(gtoken.scope, 'hello world');
    });
});
describe('.hasExpired()', () => {
    it('should exist', () => {
        const gtoken = new src_1.GoogleToken();
        assert.strictEqual(typeof gtoken.hasExpired, 'function');
    });
    it('should detect expired tokens', () => {
        const gtoken = new src_1.GoogleToken();
        assert(gtoken.hasExpired(), 'should be expired without token');
        gtoken.token = 'hello';
        assert(gtoken.hasExpired(), 'should be expired without expires_at');
        gtoken.expiresAt = (new Date().getTime()) + 10000;
        assert(!gtoken.hasExpired(), 'shouldnt be expired with future date');
        gtoken.expiresAt = (new Date().getTime()) - 10000;
        assert(gtoken.hasExpired(), 'should be expired with past date');
        gtoken.expiresAt = (new Date().getTime()) + 10000;
        gtoken.token = null;
        assert(gtoken.hasExpired(), 'should be expired with no token');
    });
});
describe('.revokeToken()', () => {
    it('should exist', () => {
        const gtoken = new src_1.GoogleToken();
        assert.strictEqual(typeof gtoken.revokeToken, 'function');
    });
    it('should run accept config properties', done => {
        const token = 'w00t';
        const scope = createRevokeMock(token);
        const gtoken = new src_1.GoogleToken();
        gtoken.token = token;
        gtoken.revokeToken(err => {
            assert.strictEqual(gtoken.token, null);
            scope.done();
            done();
        });
    });
    it('should return appropriate error with HTTP 404s', done => {
        const token = 'w00t';
        const scope = createRevokeMock(token, 404);
        const gtoken = new src_1.GoogleToken();
        gtoken.token = token;
        gtoken.revokeToken(err => {
            assert(err);
            scope.done();
            done();
        });
    });
    it('should run accept config properties with async', () => __awaiter(this, void 0, void 0, function* () {
        const token = 'w00t';
        const scope = createRevokeMock(token);
        const gtoken = new src_1.GoogleToken();
        gtoken.token = token;
        yield gtoken.revokeToken();
        assert.strictEqual(gtoken.token, null);
        scope.done();
    }));
    it('should return error when no token set', done => {
        const gtoken = new src_1.GoogleToken();
        gtoken.token = null;
        gtoken.revokeToken(err => {
            assert(err && err.message);
            done();
        });
    });
    it('should return error when no token set with async', () => __awaiter(this, void 0, void 0, function* () {
        const gtoken = new src_1.GoogleToken();
        gtoken.token = null;
        let err;
        try {
            yield gtoken.revokeToken();
        }
        catch (e) {
            err = e;
        }
        assert(err && err.message);
    }));
});
describe('.getToken()', () => {
    it('should exist', () => {
        const gtoken = new src_1.GoogleToken();
        assert.strictEqual(typeof gtoken.getToken, 'function');
    });
    it('should read .pem keyFile from file', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_KEYFILE);
        const scope = createGetTokenMock();
        gtoken.getToken((err, token) => {
            assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
            scope.done();
            done();
        });
    });
    it('should read .pem keyFile from file async', () => __awaiter(this, void 0, void 0, function* () {
        const gtoken = new src_1.GoogleToken(TESTDATA_KEYFILE);
        const scope = createGetTokenMock();
        const token = yield gtoken.getToken();
        scope.done();
        assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
    }));
    it('should return error if iss is not set with .pem', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_KEYFILENOEMAIL);
        gtoken.getToken(err => {
            assert(err);
            if (err) {
                assert.strictEqual(err.code, 'MISSING_CREDENTIALS');
                done();
            }
        });
    });
    it('should return err if neither key nor keyfile are set', done => {
        const gtoken = new src_1.GoogleToken();
        gtoken.getToken((err, token) => {
            assert(err);
            done();
        });
    });
    it('should read .json key from file', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_KEYFILEJSON);
        const scope = createGetTokenMock();
        gtoken.getToken((err, token) => {
            scope.done();
            assert.strictEqual(err, null);
            const parsed = JSON.parse(KEYJSONCONTENTS);
            assert.deepStrictEqual(gtoken.key, parsed.private_key);
            assert.deepStrictEqual(gtoken.iss, parsed.client_email);
            done();
        });
    });
    it('should accept additional claims', () => __awaiter(this, void 0, void 0, function* () {
        const opts = Object.assign(TESTDATA_KEYFILE, { additionalClaims: { fancyClaim: 'isFancy' } });
        const gtoken = new src_1.GoogleToken(opts);
        const scope = createGetTokenMock();
        const token = yield gtoken.getToken();
        scope.done();
        assert.deepStrictEqual(gtoken.key, KEYCONTENTS);
    }));
    it('should return error if iss is not set with .json', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_KEYFILENOEMAILJSON);
        gtoken.getToken(err => {
            assert(err);
            if (err) {
                assert.strictEqual(err.code, 'MISSING_CREDENTIALS');
                done();
            }
        });
    });
    it('should return cached token if not expired', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA);
        gtoken.token = 'mytoken';
        gtoken.expiresAt = new Date().getTime() + 10000;
        gtoken.getToken((err, token) => {
            assert.strictEqual(token, 'mytoken');
            done();
        });
    });
    it('should run gp12pem if .p12 file is given', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_P12);
        const scope = createGetTokenMock();
        gtoken.getToken((err, token) => {
            scope.done();
            assert.strictEqual(err, null);
            done();
        });
    });
    it('should return error if iss is not set with .p12', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_P12_NO_EMAIL);
        gtoken.getToken(err => {
            assert(err);
            if (err) {
                assert.strictEqual(err.code, 'MISSING_CREDENTIALS');
                done();
            }
        });
    });
    it('should return error if unknown file type is used', done => {
        const gtoken = new src_1.GoogleToken(TESTDATA_UNKNOWN);
        gtoken.getToken(err => {
            assert(err);
            if (err) {
                assert.strictEqual(err.code, 'UNKNOWN_CERTIFICATE_TYPE');
                done();
            }
        });
    });
    describe('request', () => {
        it('should be run with correct options', done => {
            const gtoken = new src_1.GoogleToken(TESTDATA);
            const fakeToken = 'nodeftw';
            const scope = createGetTokenMock(200, { 'access_token': fakeToken });
            gtoken.getToken((err, token) => {
                scope.done();
                assert.strictEqual(err, null);
                assert.strictEqual(token, fakeToken);
                done();
            });
        });
        it('should set and return correct properties on success', done => {
            const gtoken = new src_1.GoogleToken(TESTDATA);
            const RESPBODY = {
                access_token: 'accesstoken123',
                expires_in: 3600,
                token_type: 'Bearer'
            };
            const scope = createGetTokenMock(200, RESPBODY);
            gtoken.getToken((err, token) => {
                scope.done();
                assert.deepStrictEqual(gtoken.rawToken, RESPBODY);
                assert.strictEqual(gtoken.token, 'accesstoken123');
                assert.strictEqual(gtoken.token, token);
                assert.strictEqual(err, null);
                assert(gtoken.expiresAt);
                if (gtoken.expiresAt) {
                    assert(gtoken.expiresAt >= (new Date()).getTime());
                    assert(gtoken.expiresAt <= (new Date()).getTime() + (3600 * 1000));
                }
                done();
            });
        });
        it('should set and return correct properties on error', done => {
            const ERROR = 'An error occurred.';
            const gtoken = new src_1.GoogleToken(TESTDATA);
            const scope = createGetTokenMock(500, { error: ERROR });
            gtoken.getToken((err, token) => {
                scope.done();
                assert(err);
                assert.strictEqual(gtoken.rawToken, null);
                assert.strictEqual(gtoken.token, null);
                if (err)
                    assert.strictEqual(err.message, ERROR);
                assert.strictEqual(gtoken.expiresAt, null);
                done();
            });
        });
        it('should include error_description from remote error', done => {
            const gtoken = new src_1.GoogleToken(TESTDATA);
            const ERROR = 'error_name';
            const DESCRIPTION = 'more detailed message';
            const RESPBODY = { error: ERROR, error_description: DESCRIPTION };
            const scope = createGetTokenMock(500, RESPBODY);
            gtoken.getToken((err, token) => {
                scope.done();
                assert(err instanceof Error);
                if (err) {
                    assert.strictEqual(err.message, ERROR + ': ' + DESCRIPTION);
                    done();
                }
            });
        });
        it('should provide an appropriate error for a 404', done => {
            const gtoken = new src_1.GoogleToken(TESTDATA);
            const message = 'Request failed with status code 404';
            const scope = createGetTokenMock(404);
            gtoken.getToken((err, token) => {
                scope.done();
                assert(err instanceof Error);
                if (err)
                    assert.strictEqual(err.message, message);
                done();
            });
        });
    });
    it('should return credentials outside of getToken flow', () => __awaiter(this, void 0, void 0, function* () {
        const gtoken = new src_1.GoogleToken(TESTDATA_KEYFILEJSON);
        const creds = yield gtoken.getCredentials(KEYFILEJSON);
        assert(creds.privateKey);
        assert(creds.clientEmail);
    }));
});
function createGetTokenMock(code = 200, body) {
    return nock(GOOGLE_TOKEN_URLS[0])
        .replyContentLength()
        .post(GOOGLE_TOKEN_URLS[1], {
        grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
        assertion: /.?/
    }, { reqheaders: { 'Content-Type': 'application/x-www-form-urlencoded' } })
        .reply(code, body);
}
function createRevokeMock(token, code = 200) {
    return nock(GOOGLE_REVOKE_TOKEN_URLS[0])
        .get(GOOGLE_REVOKE_TOKEN_URLS[1])
        .query({ token })
        .reply(code);
}
//# sourceMappingURL=index.js.map