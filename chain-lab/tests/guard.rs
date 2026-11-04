use std::path::PathBuf;

use anchor_lang::{
    prelude::Pubkey,
    solana_program::{instruction::Instruction, system_program},
    AccountDeserialize, InstructionData, ToAccountMetas,
};
use hunter_guard::{accounts, instruction, ClaimReceipt, MAX_PERMIT_SLOTS};
use litesvm::{
    types::{FailedTransactionMetadata, TransactionMetadata},
    LiteSVM,
};
use solana_keypair::Keypair;
use solana_message::{Message, VersionedMessage};
use solana_signer::Signer;
use solana_transaction::versioned::VersionedTransaction;

const SLOT: u64 = 100;
const CAMPAIGN_ID: [u8; 32] = [42; 32];

fn submit(
    svm: &mut LiteSVM,
    instruction: Instruction,
    payer: &Keypair,
    issuer: Option<&Keypair>,
) -> Result<TransactionMetadata, Box<FailedTransactionMetadata>> {
    // Use a new blockhash each time so the repeat test reaches Hunter Guard.
    svm.expire_blockhash();
    let message = Message::new_with_blockhash(
        &[instruction],
        Some(&payer.pubkey()),
        &svm.latest_blockhash(),
    );
    let mut signers = vec![payer];
    signers.extend(issuer);
    let transaction = VersionedTransaction::try_new(VersionedMessage::Legacy(message), &signers)
        .expect("assemble synthetic signed transaction");
    svm.send_transaction(transaction).map_err(Box::new)
}

fn claim_instruction(
    campaign: Pubkey,
    claimant: Pubkey,
    issuer: Pubkey,
    issuer_signs: bool,
    expires_at_slot: u64,
) -> (Instruction, Pubkey) {
    let (receipt, _) = Pubkey::find_program_address(
        &[b"claim", campaign.as_ref(), claimant.as_ref()],
        &hunter_guard::ID,
    );
    let mut metas = accounts::Claim {
        campaign,
        claimant,
        issuer,
        receipt,
        system_program: system_program::ID,
    }
    .to_account_metas(None);
    let issuer_meta = metas
        .iter_mut()
        .find(|meta| meta.pubkey == issuer)
        .expect("claim instruction has an issuer account");
    issuer_meta.is_signer = issuer_signs;
    (
        Instruction::new_with_bytes(
            hunter_guard::ID,
            &instruction::Claim { expires_at_slot }.data(),
            metas,
        ),
        receipt,
    )
}

#[test]
fn guard_enforces_permits_and_once_per_wallet_on_solana() {
    let artifact = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../target/deploy/hunter_guard.so");
    let mut svm = LiteSVM::new();
    let binary = std::fs::read(&artifact)
        .unwrap_or_else(|error| panic!("read {}: {error}", artifact.display()));
    svm.add_program(hunter_guard::ID, &binary)
        .unwrap_or_else(|error| panic!("load {}: {error:?}", artifact.display()));
    svm.warp_to_slot(SLOT);

    let admin = Keypair::new();
    let claimant = Keypair::new();
    let issuer = Keypair::new();
    let wrong_issuer = Keypair::new();
    for signer in [&admin, &claimant] {
        svm.airdrop(&signer.pubkey(), 1_000_000_000)
            .expect("fund synthetic wallet");
    }
    let (campaign, _) = Pubkey::find_program_address(
        &[b"campaign", admin.pubkey().as_ref(), &CAMPAIGN_ID],
        &hunter_guard::ID,
    );
    let initialize = Instruction::new_with_bytes(
        hunter_guard::ID,
        &instruction::InitializeCampaign {
            campaign_id: CAMPAIGN_ID,
            issuer: issuer.pubkey(),
        }
        .data(),
        accounts::InitializeCampaign {
            admin: admin.pubkey(),
            campaign,
            system_program: system_program::ID,
        }
        .to_account_metas(None),
    );
    submit(&mut svm, initialize, &admin, None).expect("create isolated campaign");

    let (direct, receipt) = claim_instruction(
        campaign, claimant.pubkey(), issuer.pubkey(), false, SLOT + 30,
    );
    let missing = submit(&mut svm, direct, &claimant, None).expect_err("issuer must sign");
    assert!(missing.meta.logs.iter().any(|line| line.contains("AccountNotSigner")));
    assert!(svm.get_account(&receipt).is_none());

    let (rogue, _) = claim_instruction(
        campaign, claimant.pubkey(), wrong_issuer.pubkey(), true, SLOT + 30,
    );
    let wrong = submit(&mut svm, rogue, &claimant, Some(&wrong_issuer))
        .expect_err("only the campaign issuer may approve");
    assert!(wrong.meta.logs.iter().any(|line| line.contains("WrongIssuer")));
    assert!(svm.get_account(&receipt).is_none());

    for invalid_slot in [SLOT, SLOT + MAX_PERMIT_SLOTS + 1] {
        let (invalid, _) = claim_instruction(
            campaign, claimant.pubkey(), issuer.pubkey(), true, invalid_slot,
        );
        let expired = submit(&mut svm, invalid, &claimant, Some(&issuer))
            .expect_err("permit must have a valid expiry window");
        assert!(expired.meta.logs.iter().any(|line| line.contains("PermitOutsideWindow")));
        assert!(svm.get_account(&receipt).is_none());
    }

    let (allowed, _) = claim_instruction(
        campaign, claimant.pubkey(), issuer.pubkey(), true, SLOT + 30,
    );
    let accepted = submit(&mut svm, allowed, &claimant, Some(&issuer))
        .expect("eligible claim with both signatures succeeds");
    eprintln!("Hunter claim consumed {} compute units", accepted.compute_units_consumed);
    let recorded = svm.get_account(&receipt).expect("receipt account exists");
    assert_eq!(recorded.owner, hunter_guard::ID);
    let value = ClaimReceipt::try_deserialize(&mut recorded.data.as_slice())
        .expect("decode Hunter claim receipt");
    assert_eq!(value.campaign, campaign);
    assert_eq!(value.claimant, claimant.pubkey());
    assert_eq!(value.claimed_at_slot, SLOT);

    let (retry, _) = claim_instruction(
        campaign, claimant.pubkey(), issuer.pubkey(), true, SLOT + 31,
    );
    submit(&mut svm, retry, &claimant, Some(&issuer))
        .expect_err("fresh approval still cannot claim twice");
    assert_eq!(svm.get_account(&receipt).unwrap().data, recorded.data);
}
