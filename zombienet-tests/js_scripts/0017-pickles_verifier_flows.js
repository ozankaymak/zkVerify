const MIN_PRICE = 1000000000;
const PICKLES_SECTION = "settlementPicklesPallet";

const ReturnCode = {
    Ok: 1,
    ErrInlineProofVerificationFailed: 2,
    ErrAcceptedUnregisteredHash: 3,
    ErrVkRegistrationFailed: 4,
    ErrMissingVkHash: 5,
    ErrProofVerificationHashFailed: 6,
    ErrVkUnregistrationFailed: 7,
    ErrAcceptedHashAfterUnregister: 8,
    ErrWidthProofVerificationFailed: 9,
    ErrFalseProofVerified: 10,
    ErrValidProofNotPay: 11,
    ErrInvalidProofNotPay: 12,
};

const { init_api, submitProof, submitExtrinsic, BlockUntil, getBalance, receivedEvents } = require('zkv-lib');
const { WIDTH_0, WIDTH_1, WIDTH_2 } = require('./pickles_data.js');

function proofArgsFromVk(fixture) {
    return [{ 'Vk': fixture.VK }, fixture.PROOF, fixture.PUBS];
}

function proofArgsFromHash(vkHash, fixture) {
    return [{ 'Hash': vkHash }, fixture.PROOF, fixture.PUBS];
}

function corruptPubs(pubs) {
    const corrupted = {
        publicInput: pubs.publicInput.slice(),
        publicOutput: pubs.publicOutput.slice(),
    };
    const field = Buffer.from(corrupted.publicInput[0].slice(2), 'hex');
    field[0] ^= 1;
    corrupted.publicInput[0] = '0x' + field.toString('hex');
    return corrupted;
}

async function registerPicklesVk(api, signer, vk) {
    return await submitExtrinsic(api, api.tx.settlementPicklesPallet.registerVk(vk), signer, BlockUntil.InBlock,
        (event) => event.section == PICKLES_SECTION && event.method == "VkRegistered"
    );
}

async function unregisterPicklesVk(api, signer, vkHash) {
    return await submitExtrinsic(api, api.tx.settlementPicklesPallet.unregisterVk(vkHash), signer, BlockUntil.InBlock,
        (event) => event.section == PICKLES_SECTION && event.method == "VkUnregistered"
    );
}

async function submitValidPicklesProof(pallet, signer, name, fixture) {
    console.log(`Submitting Pickles proof: ${name}`);
    const result = await submitProof(pallet, signer, ...proofArgsFromVk(fixture));
    if (!receivedEvents(result)) {
        console.log(`Pickles proof was not verified: ${name}`);
        return false;
    }
    return true;
}

async function run(nodeName, networkInfo, _args) {
    const api = await init_api(zombie, nodeName, networkInfo);
    const keyring = new zombie.Keyring({ type: 'sr25519' });
    const alice = keyring.addFromUri('//Alice');
    const pickles = api.tx.settlementPicklesPallet;

    if (!await submitValidPicklesProof(pickles, alice, "recursion width 2 inline VK", WIDTH_2)) {
        return ReturnCode.ErrInlineProofVerificationFailed;
    }

    if (receivedEvents(await submitProof(pickles, alice, ...proofArgsFromHash('0x' + '00'.repeat(32), WIDTH_2)))) {
        return ReturnCode.ErrAcceptedUnregisteredHash;
    }

    const registerResult = await registerPicklesVk(api, alice, WIDTH_2.VK);
    if (!receivedEvents(registerResult)) {
        return ReturnCode.ErrVkRegistrationFailed;
    }
    const vkHash = registerResult.events[0].data[0].toString();
    if (!vkHash) {
        return ReturnCode.ErrMissingVkHash;
    }
    if (!receivedEvents(await submitProof(pickles, alice, ...proofArgsFromHash(vkHash, WIDTH_2)))) {
        return ReturnCode.ErrProofVerificationHashFailed;
    }
    if (!receivedEvents(await unregisterPicklesVk(api, alice, vkHash))) {
        return ReturnCode.ErrVkUnregistrationFailed;
    }
    if (receivedEvents(await submitProof(pickles, alice, ...proofArgsFromHash(vkHash, WIDTH_2)))) {
        return ReturnCode.ErrAcceptedHashAfterUnregister;
    }

    for (const [name, fixture] of [["recursion width 0", WIDTH_0], ["recursion width 1", WIDTH_1]]) {
        if (!await submitValidPicklesProof(pickles, alice, name, fixture)) {
            return ReturnCode.ErrWidthProofVerificationFailed;
        }
    }

    let balanceAlice = await getBalance(alice);
    if (!receivedEvents(await submitProof(pickles, alice, ...proofArgsFromVk(WIDTH_2)))) {
        return ReturnCode.ErrInlineProofVerificationFailed;
    }
    let newBalanceAlice = await getBalance(alice);
    if (balanceAlice - newBalanceAlice <= MIN_PRICE) {
        return ReturnCode.ErrValidProofNotPay;
    }

    balanceAlice = newBalanceAlice;
    if (receivedEvents(await submitProof(
        pickles,
        alice,
        { 'Vk': WIDTH_2.VK },
        WIDTH_2.PROOF,
        corruptPubs(WIDTH_2.PUBS)
    ))) {
        return ReturnCode.ErrFalseProofVerified;
    }
    newBalanceAlice = await getBalance(alice);
    if (balanceAlice - newBalanceAlice <= MIN_PRICE) {
        return ReturnCode.ErrInvalidProofNotPay;
    }

    return ReturnCode.Ok;
}

module.exports = { run };
