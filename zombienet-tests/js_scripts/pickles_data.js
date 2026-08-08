const fs = require('fs');
const path = require('path');

function readHex(...parts) {
    return '0x' + fs.readFileSync(path.join(__dirname, '..', '..', ...parts)).toString('hex');
}

function readFixture(name) {
    const fixture = ['verifiers', 'pickles', 'src', 'resources', name];
    const metadata = JSON.parse(
        fs.readFileSync(path.join(__dirname, '..', '..', ...fixture, 'fixture.json'), 'utf8')
    );
    return {
        PROOF: readHex(...fixture, 'proof.bin'),
        PUBS: {
            publicInput: metadata.publicInput.map((field) => '0x' + field),
            publicOutput: metadata.publicOutput.map((field) => '0x' + field),
        },
        VK: {
            verifierIndexBytes: readHex(...fixture, 'verifier-index.bin'),
            profile: 'PicklesV1',
        },
    };
}

exports.WIDTH_0 = readFixture('width0');
exports.WIDTH_1 = readFixture('width1');
exports.WIDTH_2 = readFixture('width2');

exports.PROOF = exports.WIDTH_2.PROOF;
exports.PUBS = exports.WIDTH_2.PUBS;
exports.VK = exports.WIDTH_2.VK;
