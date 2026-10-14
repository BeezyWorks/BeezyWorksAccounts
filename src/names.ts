export interface NameParts {
  firstName?: string | null
  lastName?: string | null
  displayName?: string | null
  name?: string | null
}

const clean = (s: string | null | undefined) => (s ?? '').trim()

/** What clients should show: displayName, else "first last", else Better Auth's `name`. */
export function displayNameOf(u: NameParts): string {
  return clean(u.displayName) || `${clean(u.firstName)} ${clean(u.lastName)}`.trim() || clean(u.name)
}
