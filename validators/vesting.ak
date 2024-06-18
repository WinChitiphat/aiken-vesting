use aiken/hash.{Blake2b_224, Hash}
use aiken/interval.{Finite, Interval, IntervalBound}
use aiken/list
// use aiken/string
use aiken/transaction.{
  OutputReference, ScriptContext, Spend, Transaction, TransactionId,
  ValidityRange,
}
use aiken/transaction/credential.{VerificationKey}

type Datum {
  /// POSIX time in second, e.g. 1672843961000
  lock_until: POSIXTime,
  /// Owner's credentials
  owner: VerificationKeyHash,
  /// Beneficiary's credentials
  beneficiary: VerificationKeyHash,
}

type VerificationKeyHash =
  Hash<Blake2b_224, VerificationKey>

type POSIXTime =
  Int

type Redeemer {
  msg: ByteArray,
}

validator {
  fn vesting(datum: Datum, _redeemer: Redeemer, context: ScriptContext) -> Bool {
    // In principle, scripts can be used for different purpose (e.g. minting
    // assets). Here we make sure it's only used when 'spending' from a eUTxO
    when context.purpose is {
      Spend(_) -> or {
          must_be_signed_by(context.transaction, datum.owner),
          and {
            must_be_signed_by(context.transaction, datum.beneficiary),
            must_start_after(
              context.transaction.validity_range,
              datum.lock_until,
            ),
          },
        }
      _ -> False
    }
  }
}

fn must_be_signed_by(transaction: Transaction, vk: VerificationKeyHash) {
  list.has(transaction.extra_signatories, vk)
}

fn must_start_after(range: ValidityRange, lock_expiration_time: POSIXTime) {
  when range.lower_bound.bound_type is {
    Finite(tx_earliest_time) -> lock_expiration_time <= tx_earliest_time
    _ -> False
  }
}

test must_start_after_succeed_when_lower_bound_is_after() {
  must_start_after(interval.after(2), 1)
}

test must_start_after_succeed_when_lower_bound_is_equal() {
  must_start_after(interval.after(2), 2)
}

test must_start_after_fail_when_lower_bound_is_before() {
  !must_start_after(interval.after(2), 3)
}

test vesting_example() {
  let datum =
    Datum {
      lock_until: 1000,
      owner: #"00000000000000000000000000000000000000000000000000000000",
      beneficiary: #"00000000000000000000000000000000000000000000000000000000",
    }
  let redeemer = Redeemer { msg: "hi" }
  let placeholder_utxo =
    OutputReference { transaction_id: TransactionId(""), output_index: 0 }
  let context =
    ScriptContext {
      purpose: Spend(placeholder_utxo),
      transaction: transaction.placeholder()
        |> fn(transaction) {
            Transaction { ..transaction, extra_signatories: [datum.owner] }
          },
    }
  vesting(datum, redeemer, context)
}
