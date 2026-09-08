import type { SupabaseClient } from '@supabase/supabase-js';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const mocks = vi.hoisted(() => ({ balance: vi.fn(), send: vi.fn(), provider: vi.fn(), webhook: vi.fn() }));
vi.mock('@/app/api/cron/monitor-payments/balance-checkers', () => ({ checkBalance: mocks.balance }));
vi.mock('@/lib/crypto/require-key', () => ({ tryRequireEncryptionKey: () => ({ ok: true, key: 'synthetic' }) }));
vi.mock('@/lib/crypto/encryption', () => ({ decrypt: () => 'synthetic-not-a-chain-key' }));
vi.mock('@/lib/wallets/system-wallet', () => ({ getCommissionWallet: () => 'synthetic-fee' }));
vi.mock('@/lib/entitlements/service', () => ({ isBusinessPaidTier: async () => false }));
vi.mock('@/lib/webhooks/service', () => ({ sendPaymentWebhook: mocks.webhook }));
vi.mock('@/lib/blockchain/providers', () => {
  class EthereumProvider {
    sendTransaction = mocks.send;
    sendSplitTransaction = mocks.send;
  }
  return { getProvider: mocks.provider, getRpcUrl: () => 'http://localhost',
    EthereumProvider, SolanaProvider: class {}, BitcoinProvider: class {} };
});
import { EthereumProvider } from '@/lib/blockchain/providers';
import { forwardPaymentSecurely } from './secure-forwarding';

function database(options: { recoveryError?: boolean; competingStatus?: string } = {}) {
  const payment: Record<string, unknown> = { id: 'synthetic-payment', business_id: 'synthetic-business',
    status: 'confirmed', blockchain: 'ETH', crypto_amount: 20, amount: 20,
    payment_address: 'synthetic-source', merchant_wallet_address: 'synthetic-merchant', metadata: {} };
  const address = { payment_id: payment.id, address: payment.payment_address, cryptocurrency: 'ETH',
    merchant_wallet: payment.merchant_wallet_address, commission_wallet: 'synthetic-fee',
    encrypted_private_key: 'synthetic-encrypted' };
  const writes: Array<Record<string, unknown>> = [];
  const client = { from(table: string) {
    let values: Record<string, unknown> | undefined;
    let single = false;
    const filters: Array<[string, unknown]> = [];
    const query = {
      select() { return query; }, update(patch: Record<string, unknown>) { values = patch; return query; },
      eq(key: string, value: unknown) { filters.push([key, value]); return query; },
      single() { single = true; return query; },
      then(resolve: (value: unknown) => unknown, reject?: (reason: unknown) => unknown) {
        if (values && table === 'payments') {
          if (values.status === 'confirmed') {
            if (options.competingStatus) payment.status = options.competingStatus;
            if (options.recoveryError) return Promise.resolve({ data: null, error: new Error('synthetic DB unavailable') }).then(resolve, reject);
          }
          const match = filters.every(([key, value]) => payment[key] === value);
          if (match) { Object.assign(payment, values); writes.push({ ...values }); }
          return Promise.resolve({ data: match ? [{ ...payment }] : [], error: null }).then(resolve, reject);
        }
        return Promise.resolve({ data: single ? { ...(table === 'payments' ? payment : address) } : [], error: null }).then(resolve, reject);
      },
    };
    return query;
  } };
  return { client: client as unknown as SupabaseClient, payment, writes };
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.spyOn(console, 'log').mockImplementation(() => {});
  vi.spyOn(console, 'warn').mockImplementation(() => {});
  vi.spyOn(console, 'error').mockImplementation(() => {});
  vi.stubGlobal('fetch', vi.fn(async () => { throw new Error('No external network allowed'); }));
  mocks.balance.mockResolvedValue(20);
  mocks.send.mockResolvedValue('synthetic-tx-hash');
  mocks.webhook.mockResolvedValue({ success: true });
  mocks.provider.mockImplementation(() => new EthereumProvider('http://localhost'));
});
afterEach(() => { vi.unstubAllGlobals(); vi.restoreAllMocks(); });

describe('secure forwarding requires a known spendable balance', () => {
  it.each([null, undefined, NaN, Infinity, -Infinity, '20'])('never broadcasts for an invalid oracle value %s', async value => {
    const db = database(); mocks.balance.mockResolvedValue(value);
    const result = await forwardPaymentSecurely(db.client, 'synthetic-payment');
    expect(result.success).toBe(false);
    expect(result.error).toMatch(/balance/i);
    expect(mocks.send).not.toHaveBeenCalled();
    expect(mocks.provider).not.toHaveBeenCalled();
    expect(mocks.webhook).not.toHaveBeenCalled();
    expect(db.payment.status).toBe('confirmed');
  });
  it('defers a failed read then allows one verified retry', async () => {
    const db = database(); mocks.balance.mockRejectedValueOnce(new Error('synthetic timeout'));
    expect((await forwardPaymentSecurely(db.client, 'synthetic-payment')).success).toBe(false);
    expect(mocks.send).not.toHaveBeenCalled();
    expect(db.payment.status).toBe('confirmed');
    expect((await forwardPaymentSecurely(db.client, 'synthetic-payment')).success).toBe(true);
    expect(db.payment.status).toBe('forwarded');
    expect(mocks.send).toHaveBeenCalledTimes(1);
    expect((await forwardPaymentSecurely(db.client, 'synthetic-payment')).success).toBe(false);
    expect(mocks.send).toHaveBeenCalledTimes(1);
  });
  it('still refuses to broadcast if releasing its claim fails', async () => {
    const db = database({ recoveryError: true }); mocks.balance.mockRejectedValue(new Error('synthetic timeout'));
    const result = await forwardPaymentSecurely(db.client, 'synthetic-payment');
    expect(result.success).toBe(false);
    expect(db.payment.status).toBe('forwarding');
    expect(mocks.send).not.toHaveBeenCalled();
    expect(mocks.webhook).not.toHaveBeenCalled();
  });
  it('does not overwrite another worker when releasing a failed-read claim', async () => {
    const db = database({ competingStatus: 'forwarded' }); mocks.balance.mockRejectedValue(new Error('synthetic timeout'));
    expect((await forwardPaymentSecurely(db.client, 'synthetic-payment')).success).toBe(false);
    expect(db.payment.status).toBe('forwarded');
    expect(mocks.send).not.toHaveBeenCalled();
  });
  it.each([0, -1, 19])('does not broadcast a known insufficient balance %s', async balance => {
    const db = database(); mocks.balance.mockResolvedValue(balance);
    expect((await forwardPaymentSecurely(db.client, 'synthetic-payment')).success).toBe(false);
    expect(mocks.send).not.toHaveBeenCalled();
    expect(db.payment.status).toBe('confirmed');
  });
  it('splits the verified overpayment and preserves payout destinations', async () => {
    const db = database(); mocks.balance.mockResolvedValue(21);
    const result = await forwardPaymentSecurely(db.client, 'synthetic-payment');
    expect(result.success).toBe(true);
    expect(result.merchantAmount).toBe(20.79);
    expect(result.platformFee).toBe(0.21);
    expect(mocks.send.mock.calls[0][1]).toEqual([
      { address: 'synthetic-merchant', amount: '20.79' }, { address: 'synthetic-fee', amount: '0.21' },
    ]);
  });
});
