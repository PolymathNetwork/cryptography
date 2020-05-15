use crate::mercat::ConfidentialTxState;

use bulletproofs::ProofError;
use failure::{Backtrace, Context, Fail};

use sp_std::fmt;

/// Represents an error resulted from asset value encryption,
/// decryption, or proof generation.
#[derive(Debug)]
pub struct Error {
    inner: Context<ErrorKind>,
}

impl Error {
    #[inline]
    pub fn kind(&self) -> &ErrorKind {
        self.inner.get_context()
    }
}

impl From<ErrorKind> for Error {
    fn from(kind: ErrorKind) -> Error {
        Error {
            inner: Context::new(kind),
        }
    }
}

impl From<Context<ErrorKind>> for Error {
    fn from(inner: Context<ErrorKind>) -> Error {
        Error { inner: inner }
    }
}

impl Fail for Error {
    fn cause(&self) -> Option<&dyn Fail> {
        self.inner.cause()
    }

    #[inline]
    fn backtrace(&self) -> Option<&Backtrace> {
        self.inner.backtrace()
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.inner, f)
    }
}

#[derive(Fail, Clone, Debug, Eq, PartialEq)]
pub enum ErrorKind {
    /// Unable to encrypt a plain text outside of the valid range.
    #[fail(display = "Unable to encrypt a plain text outside of the valid range")]
    PlainTextRangeError,

    /// Encrypted value was not found within the valid range.
    #[fail(display = "Encrypted value was not found within the valid range")]
    CipherTextDecryptionError,

    /// A proof verification error occured.
    #[fail(display = "A proof verification error occured")]
    VerificationError,

    /// Failed to verify a correctness proof.
    #[fail(
        display = "Failed to verify the check number {} of the correctness proof",
        check
    )]
    CorrectnessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a wellformedness proof.
    #[fail(
        display = "Failed to verify the check number {} of the wellformedness proof",
        check
    )]
    WellformednessFinalResponseVerificationError { check: u16 },

    /// Failed to verify a ciphertext refreshment proof.
    #[fail(
        display = "Failed to verify the check number {} of the ciphertext refreshment proof",
        check
    )]
    CiphertextRefreshmentFinalResponseVerificationError { check: u16 },

    /// Failed to verify an encrypting the same value proof.
    #[fail(
        display = "Failed to verify the check number {} of the encrypting the same value proof",
        check
    )]
    EncryptingSameValueFinalResponseVerificationError { check: u16 },

    /// A range proof error occured.
    #[fail(display = "A range proof error occured: {}", _0)]
    ProvingError(#[cause] ProofError),

    #[fail(display = "This method is not implemented yet")]
    NotImplemented,
    #[fail(display = "Received an invalid previous state: {:?}", state)]
    InvalidPreviousState { state: ConfidentialTxState },
    #[fail(
        display = "Expected to receive {:?} form the sender, got {:?}",
        expected_amount, received_amount
    )]
    TransactionAmountMismatch {
        expected_amount: u32,
        received_amount: u32,
    },

    #[fail(display = "Public keys in the memo and the account are different.")]
    InputPubKeyMismatch,

    #[fail(
        display = "Transaction amount {} must be equal or greater than {}",
        transaction_amount, balance
    )]
    NotEnoughFund {
        balance: u32,
        transaction_amount: u32,
    },

    #[fail(display = "The account does not match the account on the transaction")]
    AccountIdMismatch,
}

pub type Fallible<T, E = Error> = std::result::Result<T, E>;