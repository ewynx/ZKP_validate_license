import { Licences } from './Licenses';
import {
  isReady,
  shutdown,
  Field,
  Mina,
  PrivateKey,
  PublicKey,
  AccountUpdate,
  MerkleTree,
} from 'snarkyjs';

/*
 * This file specifies how to test the `Add` example smart contract. It is safe to delete this file and replace
 * with your own tests.
 *
 * See https://docs.minaprotocol.com/zkapps for more info.
 */

let proofsEnabled = false;

describe('Add', () => {
  let deployerAccount: PublicKey,
    deployerKey: PrivateKey,
    zkAppAddress: PublicKey,
    zkAppPrivateKey: PrivateKey,
    zkApp: Licences,
    authoritiesMerkleTree: MerkleTree,
    licenseAuthoritiesTree: MerkleTree,
    auth0: PrivateKey,
    auth1: PrivateKey,
    auth2: PrivateKey;

  beforeAll(async () => {
    await isReady;
    if (proofsEnabled) Licences.compile();
  });

  beforeEach(() => {
    const Local = Mina.LocalBlockchain({ proofsEnabled });
    Mina.setActiveInstance(Local);
    ({ privateKey: deployerKey, publicKey: deployerAccount } =
      Local.testAccounts[0]);
    zkAppPrivateKey = PrivateKey.random();
    zkAppAddress = zkAppPrivateKey.toPublicKey();
    zkApp = new Licences(zkAppAddress);
    authoritiesMerkleTree = new MerkleTree(3);
    licenseAuthoritiesTree = new MerkleTree(8);
    auth0 = PrivateKey.random();
    auth1 = PrivateKey.random();
    auth2 = PrivateKey.random();
  });

  afterAll(() => {
    // `shutdown()` internally calls `process.exit()` which will exit the running Jest process early.
    // Specifying a timeout of 0 is a workaround to defer `shutdown()` until Jest is done running all tests.
    // This should be fixed with https://github.com/MinaProtocol/mina/issues/10943
    setTimeout(shutdown, 0);
  });

  async function localDeploy() {
    const txn = await Mina.transaction(deployerAccount, () => {
      AccountUpdate.fundNewAccount(deployerAccount);
      zkApp.deploy();
      authoritiesMerkleTree.setLeaf(0n, auth0.toPublicKey().x);
      authoritiesMerkleTree.setLeaf(1n, auth1.toPublicKey().x);
      authoritiesMerkleTree.setLeaf(2n, auth2.toPublicKey().x);
      zkApp.initState(auth0, auth1, auth2, licenseAuthoritiesTree.getRoot());
    });
    await txn.prove();
    // this tx needs .sign(), because `deploy()` adds an account update that requires signature authorization
    await txn.sign([deployerKey, zkAppPrivateKey]).send();
  }

  it('generates and deploys the `Add` smart contract', async () => {
    await localDeploy();
    const num = zkApp.nextIndex.get();
    expect(num).toEqual(Field(0));
  });

  // TODO add tests
  /*
  it('correctly updates the num state on the `Add` smart contract', async () => {
    await localDeploy();

    // update transaction
    const txn = await Mina.transaction(senderAccount, () => {
      zkApp.update();
    });
    await txn.prove();
    await txn.sign([senderKey]).send();

    const updatedNum = zkApp.num.get();
    expect(updatedNum).toEqual(Field(3));
  });
  */
});
