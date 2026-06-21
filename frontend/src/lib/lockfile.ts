const LOCKFILE_PATTERNS: { pattern: RegExp; ecosystem: string }[] = [
  { pattern: /^package-lock\.json$/i, ecosystem: 'npm' },
  { pattern: /^yarn\.lock$/i, ecosystem: 'npm' },
  { pattern: /^pnpm-lock\.yaml$/i, ecosystem: 'npm' },
  { pattern: /^requirements\.txt$/i, ecosystem: 'PyPI' },
  { pattern: /^Pipfile\.lock$/i, ecosystem: 'PyPI' },
  { pattern: /^poetry\.lock$/i, ecosystem: 'PyPI' },
  { pattern: /^go\.sum$/i, ecosystem: 'Go' },
  { pattern: /^Cargo\.lock$/i, ecosystem: 'crates.io' },
  { pattern: /^Gemfile\.lock$/i, ecosystem: 'RubyGems' },
]

export function detectEcosystem(filename: string): string | null {
  const match = LOCKFILE_PATTERNS.find(({ pattern }) => pattern.test(filename))
  return match?.ecosystem ?? null
}

export function isSupportedLockfile(filename: string): boolean {
  return detectEcosystem(filename) !== null
}

export const SUPPORTED_LOCKFILES = [
  'package-lock.json',
  'yarn.lock',
  'pnpm-lock.yaml',
  'requirements.txt',
  'Pipfile.lock',
  'poetry.lock',
  'go.sum',
  'Cargo.lock',
  'Gemfile.lock',
]
