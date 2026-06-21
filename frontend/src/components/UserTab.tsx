import { useClerk, useUser } from '@clerk/react'
import { LogOut, Shield } from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { createPortal } from 'react-dom'
import { useNavigate } from '@tanstack/react-router'

import { Button } from '@/components/ui/button'
import { cn } from '@/lib/utils'

type OAuthProvider = 'github' | 'google' | 'unknown'

function getOAuthProvider(
  provider: string | undefined,
): OAuthProvider {
  if (!provider) return 'unknown'
  if (provider.includes('github')) return 'github'
  if (provider.includes('google')) return 'google'
  return 'unknown'
}

function providerLabel(provider: OAuthProvider) {
  switch (provider) {
    case 'github':
      return 'GitHub'
    case 'google':
      return 'Google'
    default:
      return 'Account'
  }
}

type ClerkUser = NonNullable<ReturnType<typeof useUser>['user']>

function resolveDisplayName(user: ClerkUser): string {
  const fromUser =
    user.fullName?.trim() ||
    [user.firstName, user.lastName].filter(Boolean).join(' ').trim()
  if (fromUser) return fromUser

  const external = user.externalAccounts[0]
  const fromExternal =
    [external?.firstName, external?.lastName].filter(Boolean).join(' ').trim() ||
    external?.username?.trim()
  if (fromExternal) return fromExternal

  const email = user.primaryEmailAddress?.emailAddress
  if (email) {
    const localPart = email.split('@')[0]?.trim()
    if (localPart) return localPart
  }

  return 'User'
}

function resolveAvatarUrl(user: ClerkUser): string | null {
  for (const account of user.externalAccounts) {
    if (account.imageUrl) {
      return account.imageUrl
    }
  }

  if (user.hasImage && user.imageUrl) {
    return user.imageUrl
  }

  if (user.imageUrl && !user.imageUrl.includes('type=default')) {
    return user.imageUrl
  }

  return null
}

function DefaultAvatar({ className }: { className?: string }) {
  return (
    <div
      className={cn(
        'flex items-center justify-center rounded-full bg-gradient-to-br from-primary to-accent-foreground text-primary-foreground',
        className,
      )}
      aria-hidden
    >
      <Shield className="h-[55%] w-[55%]" strokeWidth={1.75} />
    </div>
  )
}

function UserAvatar({
  imageUrl,
  name,
  className,
}: {
  imageUrl?: string | null
  name: string
  className?: string
}) {
  const [imageFailed, setImageFailed] = useState(false)

  useEffect(() => {
    setImageFailed(false)
  }, [imageUrl])

  if (!imageUrl || imageFailed) {
    return <DefaultAvatar className={className} />
  }

  return (
    <img
      src={imageUrl}
      alt={name}
      referrerPolicy="no-referrer"
      className={cn('rounded-full object-cover', className)}
      onError={() => setImageFailed(true)}
    />
  )
}

export function UserTab() {
  const { user, isLoaded } = useUser()
  const { signOut } = useClerk()
  const navigate = useNavigate()
  const [open, setOpen] = useState(false)
  const [signingOut, setSigningOut] = useState(false)
  const containerRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (!open) return

    function handlePointerDown(event: MouseEvent) {
      if (
        containerRef.current &&
        !containerRef.current.contains(event.target as Node)
      ) {
        setOpen(false)
      }
    }

    function handleEscape(event: KeyboardEvent) {
      if (event.key === 'Escape') {
        setOpen(false)
      }
    }

    document.addEventListener('mousedown', handlePointerDown)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('mousedown', handlePointerDown)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [open])

  if (!isLoaded || !user) {
    return null
  }

  const displayName = resolveDisplayName(user)
  const email = user.primaryEmailAddress?.emailAddress
  const oauthProvider = getOAuthProvider(
    user.externalAccounts[0]?.provider ??
      user.externalAccounts.find((account) => account.imageUrl)?.provider,
  )
  const avatarUrl = resolveAvatarUrl(user)

  async function handleSignOut() {
    setSigningOut(true)
    try {
      await signOut()
      navigate({ to: '/sign-in', replace: true })
    } finally {
      setSigningOut(false)
      setOpen(false)
    }
  }

  return createPortal(
    <div
      ref={containerRef}
      className="fixed bottom-4 left-4 z-[100] sm:bottom-6 sm:left-6"
    >
      {open && (
        <div
          className="absolute bottom-full left-0 mb-3 w-72 overflow-hidden rounded-xl border border-border bg-card shadow-lg"
          role="menu"
          aria-label="User menu"
        >
          <div className="flex items-center gap-3 border-b border-border px-4 py-4">
            <UserAvatar
              imageUrl={avatarUrl}
              name={displayName}
              className="h-11 w-11 shrink-0"
            />
            <div className="min-w-0 text-left">
              <p className="truncate text-sm font-medium text-foreground">
                {displayName}
              </p>
              {email && (
                <p className="truncate text-xs text-muted-foreground">
                  {email}
                </p>
              )}
              <p className="mt-1 text-xs text-muted-foreground">
                Signed in with {providerLabel(oauthProvider)}
              </p>
            </div>
          </div>

          <div className="p-2">
            <Button
              type="button"
              variant="ghost"
              className="w-full justify-start gap-2 text-destructive hover:bg-destructive/10 hover:text-destructive"
              onClick={handleSignOut}
              disabled={signingOut}
              role="menuitem"
            >
              <LogOut className="h-4 w-4" />
              {signingOut ? 'Signing out…' : 'Log out'}
            </Button>
          </div>
        </div>
      )}

      <button
        type="button"
        className={cn(
          'flex items-center gap-2.5 rounded-full border border-border bg-card/95 px-2 py-2 pl-2 pr-4 shadow-md backdrop-blur-sm transition-colors hover:border-primary/40 hover:bg-card',
          open && 'border-primary/40 ring-2 ring-ring/40',
        )}
        onClick={() => setOpen((current) => !current)}
        aria-expanded={open}
        aria-haspopup="menu"
        aria-label="Open user menu"
      >
        <UserAvatar
          imageUrl={avatarUrl}
          name={displayName}
          className="h-9 w-9"
        />
        <span className="max-w-[10rem] truncate text-sm font-medium text-foreground">
          {displayName}
        </span>
      </button>
    </div>,
    document.body,
  )
}
