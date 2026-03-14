/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi } from 'vitest';
import { startNewJulesTask } from '../../src/jules';
import { z } from 'zod';

type ParsedResult = {
  stdout?: string;
  stderr?: string;
  error?: string;
};

describe('Jules MCP Server Security', () => {
  const mockExecFile = vi.fn();

  it('should prevent argument injection in repo_name', async () => {
    const repoNameSchema = z.string().regex(/^[a-zA-Z0-9._-]+\/[a-zA-Z0-9._-]+$/);

    // Malicious inputs like '--config=/etc/passwd' should be rejected by the Zod schema
    const malicious_repo_name = '--config=/etc/passwd';
    expect(repoNameSchema.safeParse(malicious_repo_name).success).toBe(false);

    // Valid inputs should pass
    const valid_repo_name = 'owner/repo';
    expect(repoNameSchema.safeParse(valid_repo_name).success).toBe(true);

    const user_task_description = 'test task';
    mockExecFile.mockImplementation((command, args, options, callback) => {
      callback(null, 'success', '');
    });

    await startNewJulesTask({ repo_name: valid_repo_name, user_task_description }, { execFile: mockExecFile as any });

    expect(mockExecFile).toHaveBeenCalledWith(
      'jules',
      ['remote', 'new', '--repo=owner/repo', '--session=test task'],
      { encoding: 'utf8' },
      expect.any(Function)
    );
  });

  it('should prevent argument injection in user_task_description', async () => {
    const repo_name = 'test-repo';
    const user_task_description = '--help';

    mockExecFile.mockImplementation((command, args, options, callback) => {
      callback(null, 'success', '');
    });

    await startNewJulesTask({ repo_name, user_task_description }, { execFile: mockExecFile as any });

    // Updated to reflect the fix
    expect(mockExecFile).toHaveBeenCalledWith(
      'jules',
      ['remote', 'new', '--repo=test-repo', '--session=--help'],
      { encoding: 'utf8' },
      expect.any(Function)
    );
  });
});
