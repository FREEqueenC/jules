/**
 * @license
 * Copyright 2025 Google LLC
 * SPDX-License-Identifier: Apache-2.0
 */

import { describe, it, expect, vi } from 'vitest';
import { startNewJulesTask } from '../../src/jules';

type ParsedResult = {
  stdout?: string;
  stderr?: string;
  error?: string;
};

describe('Jules MCP Server Security', () => {
  const mockExecFile = vi.fn();

  it('should prevent argument injection in repo_name', async () => {
    const repo_name = '--config=/etc/passwd';
    const user_task_description = 'test task';

    mockExecFile.mockImplementation((command, args, options, callback) => {
      callback(null, 'success', '');
    });

    await startNewJulesTask({ repo_name, user_task_description }, { execFile: mockExecFile as any });

    // Updated to reflect the fix
    expect(mockExecFile).toHaveBeenCalledWith(
      'jules',
      ['remote', 'new', '--repo=--config=/etc/passwd', '--session=test task'],
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
