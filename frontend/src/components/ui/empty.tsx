import * as React from 'react'
import { cn } from '@/lib/utils'

function Empty({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="empty"
      className={cn('flex flex-col items-center gap-4 text-center', className)}
      {...props}
    />
  )
}

function EmptyHeader({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="empty-header"
      className={cn('flex flex-col items-center gap-3', className)}
      {...props}
    />
  )
}

interface EmptyMediaProps extends React.ComponentProps<'div'> {
  variant?: 'default' | 'icon'
}

function EmptyMedia({ className, variant = 'default', ...props }: EmptyMediaProps) {
  return (
    <div
      data-slot="empty-media"
      className={cn(
        variant === 'icon' &&
          'flex h-12 w-12 items-center justify-center rounded-xl border border-border bg-muted text-muted-foreground',
        className,
      )}
      {...props}
    />
  )
}

function EmptyTitle({ className, ...props }: React.ComponentProps<'p'>) {
  return (
    <p
      data-slot="empty-title"
      className={cn('text-sm font-semibold text-foreground', className)}
      {...props}
    />
  )
}

function EmptyDescription({ className, ...props }: React.ComponentProps<'p'>) {
  return (
    <p
      data-slot="empty-description"
      className={cn('max-w-xs text-sm text-muted-foreground', className)}
      {...props}
    />
  )
}

function EmptyContent({ className, ...props }: React.ComponentProps<'div'>) {
  return (
    <div
      data-slot="empty-content"
      className={cn('flex flex-col items-center gap-2', className)}
      {...props}
    />
  )
}

export { Empty, EmptyHeader, EmptyMedia, EmptyTitle, EmptyDescription, EmptyContent }
