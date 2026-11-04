use anchor_lang::prelude::*;

// Fixture address for the in-process Solana lab.
declare_id!("4hCf4sWupLUJVb28BwSwxsthf2rFfvnkLPkuvfkeAzU8");

pub const MAX_PERMIT_SLOTS: u64 = 150;

#[program]
pub mod hunter_guard {
    use super::*;

    pub fn initialize_campaign(
        ctx: Context<InitializeCampaign>,
        campaign_id: [u8; 32],
        issuer: Pubkey,
    ) -> Result<()> {
        require!(
            issuer != Pubkey::default() && issuer != ctx.accounts.admin.key(),
            HunterError::InvalidIssuer
        );
        let campaign = &mut ctx.accounts.campaign;
        campaign.admin = ctx.accounts.admin.key();
        campaign.issuer = issuer;
        campaign.campaign_id = campaign_id;
        Ok(())
    }

    pub fn claim(ctx: Context<Claim>, expires_at_slot: u64) -> Result<()> {
        let slot = Clock::get()?.slot;
        require!(
            matches!(expires_at_slot.checked_sub(slot), Some(1..=MAX_PERMIT_SLOTS)),
            HunterError::PermitOutsideWindow
        );
        require!(
            ctx.accounts.claimant.key() != ctx.accounts.issuer.key(),
            HunterError::IssuerCannotClaim
        );

        let receipt = &mut ctx.accounts.receipt;
        receipt.campaign = ctx.accounts.campaign.key();
        receipt.claimant = ctx.accounts.claimant.key();
        receipt.claimed_at_slot = slot;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(campaign_id: [u8; 32])]
pub struct InitializeCampaign<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,
    #[account(
        init,
        payer = admin,
        space = 8 + Campaign::INIT_SPACE,
        seeds = [b"campaign", admin.key().as_ref(), campaign_id.as_ref()],
        bump
    )]
    pub campaign: Account<'info, Campaign>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(
        seeds = [b"campaign", campaign.admin.as_ref(), campaign.campaign_id.as_ref()],
        bump
    )]
    pub campaign: Account<'info, Campaign>,
    #[account(mut)]
    pub claimant: Signer<'info>,
    #[account(address = campaign.issuer @ HunterError::WrongIssuer)]
    pub issuer: Signer<'info>,
    #[account(
        init,
        payer = claimant,
        space = 8 + ClaimReceipt::INIT_SPACE,
        seeds = [b"claim", campaign.key().as_ref(), claimant.key().as_ref()],
        bump
    )]
    pub receipt: Account<'info, ClaimReceipt>,
    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct Campaign {
    pub admin: Pubkey,
    pub issuer: Pubkey,
    pub campaign_id: [u8; 32],
}

#[account]
#[derive(InitSpace)]
pub struct ClaimReceipt {
    pub campaign: Pubkey,
    pub claimant: Pubkey,
    pub claimed_at_slot: u64,
}

#[error_code]
pub enum HunterError {
    #[msg("Choose a separate permit issuer key")]
    InvalidIssuer,
    #[msg("The signer is not the issuer configured for this campaign")]
    WrongIssuer,
    #[msg("The permit has expired or its expiry is too far in the future")]
    PermitOutsideWindow,
    #[msg("The permit issuer cannot claim from its own campaign")]
    IssuerCannotClaim,
}
