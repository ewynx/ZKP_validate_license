import {
  Field,
  SmartContract,
  state,
  State,
  method,
  PublicKey,
  MerkleWitness,
  PrivateKey,
  MerkleTree,
  Signature,
  UInt64,
  Poseidon,
} from 'snarkyjs';

// 256 leaves should be enough to have 1 per country
export class MerkleWitness8 extends MerkleWitness(8) {}
// This is for the AuthorityMerkleTree
export class MerkleWitness3 extends MerkleWitness(3) {}

/**
 *
 *
 *
 */
export class Licences extends SmartContract {
  // There are 3 authority pubkeys. If >=2 out of 3 sign, it's accepted
  // This contains the root of the Merkle Tree containing those 3 pubKeys
  @state(Field) authRoot = State<Field>();
  // Storing valid licence signers (can be countries or other entities)
  @state(Field) nextIndex = State<Field>();
  @state(Field) licenseAuthoritiesRoot = State<Field>();

  @method initState(
    auth0Secret: PrivateKey,
    auth1Secret: PrivateKey,
    auth2Secret: PrivateKey,
    initLicenseAuthoritiesRoot: Field
  ) {
    // store the 3 keys in a MerkleTree. In this contract we keep the root
    let tree = new MerkleTree(3);
    // TODO this could also be done by directly passing in the root and storing it
    tree.setLeaf(0n, auth0Secret.toPublicKey().x);
    tree.setLeaf(1n, auth1Secret.toPublicKey().x);
    tree.setLeaf(2n, auth2Secret.toPublicKey().x);
    this.authRoot.set(tree.getRoot());

    this.licenseAuthoritiesRoot.set(initLicenseAuthoritiesRoot);
    this.nextIndex.set(Field(0));
  }

  @method addLicenseAuthority(
    pubKeys: PublicKey[],
    signatures: Signature[],
    signerWitnesses: MerkleWitness3[], // to prove they are actually valid witnesses
    newLicenseAuthority: PublicKey,
    newLicenseWitness: MerkleWitness8
  ) {
    // 1. signatures must be length at least 2. Pubkey of signers can be destilled from signatures
    UInt64.from(signatures.length).assertGreaterThanOrEqual(UInt64.from(2));

    const authRoot = this.authRoot.get();
    this.authRoot.assertEquals(authRoot);
    // 2. per entry in signer array there is a check on the witness
    for (let index in signatures) {
      let pubKey = pubKeys[index];
      signerWitnesses[index].calculateRoot(pubKey.x).equals(authRoot); // That PubKey is indeed one of the authorities
      signatures[index].verify(pubKey, [newLicenseAuthority.x]).assertTrue(); // The msg was indeed signed by that PubKey
    }

    // 3. authorityWitness index must be equal to nextIndex
    const nextIndex = this.nextIndex.get();
    this.nextIndex.assertEquals(nextIndex);
    nextIndex.assertEquals(newLicenseWitness.calculateIndex());

    // 4. update root value
    this.licenseAuthoritiesRoot.set(
      newLicenseWitness.calculateRoot(newLicenseAuthority.x)
    );
  }

  // License argument is a hash of some data that represents the license
  @method verifyLicense(
    licenseAuthorityWitness: MerkleWitness8,
    licenseAuthorityPubkey: PublicKey,
    signedLicense: Signature,
    license: Field
  ) {
    // 1. verify licenseAuthority
    this.licenseAuthoritiesRoot.assertEquals(
      licenseAuthorityWitness.calculateRoot(licenseAuthorityPubkey.x)
    );

    // 2. verify signature
    signedLicense.verify(licenseAuthorityPubkey, license.toFields());
  }
}
