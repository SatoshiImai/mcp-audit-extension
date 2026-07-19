import { describe, it, expect } from 'vitest';
import { AuditHost } from '../host/auditHost.js';
import { DEFAULT_L1_CAPABILITY, type AuditCapability } from './capability.js';

// Bidirectional capability exchange (§6.1): the tool offers a supported capability and the host
// returns its requirement plus whether the offer satisfies it. Mismatch handling is left to the
// orchestrator; the host never blocks the exchange itself.
const L2_REQUIRED: AuditCapability = { ...DEFAULT_L1_CAPABILITY, level: 'L2' };
const TOOL_L1: AuditCapability = { ...DEFAULT_L1_CAPABILITY, level: 'L1' };
const TOOL_L2: AuditCapability = { ...DEFAULT_L1_CAPABILITY, level: 'L2' };

describe('capability negotiation — bidirectional exchange', () => {
  it('an L1-requiring host is satisfied by an L1 tool', () => {
    const result = new AuditHost('t#d').negotiate(TOOL_L1);
    expect(result.satisfied).toBe(true);
    expect(result.required.level).toBe('L1');
  });

  it('an L1-requiring host is satisfied by an L2 tool (safe downgrade, L1 ⊆ L2)', () => {
    expect(new AuditHost('t#d').negotiate(TOOL_L2).satisfied).toBe(true);
  });

  it('an L2-requiring host is not satisfied by an L1 tool (the orchestrator decides)', () => {
    const result = new AuditHost('t#l2', L2_REQUIRED).negotiate(TOOL_L1);
    expect(result.satisfied).toBe(false);
    expect(result.required.level).toBe('L2');
  });

  it('an L2-requiring host is satisfied by an L2 tool', () => {
    expect(new AuditHost('t#l2', L2_REQUIRED).negotiate(TOOL_L2).satisfied).toBe(true);
  });
});
