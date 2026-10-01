import { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import './app-dialogs.css'

export type DialogTone = 'info' | 'success' | 'warning' | 'danger'

type ConfirmOptions = {
  title: string
  message: string
  confirmLabel?: string
  cancelLabel?: string
  tone?: DialogTone
}

type NotifyOptions = {
  title: string
  message: string
  buttonLabel?: string
  tone?: DialogTone
}

type DialogRequest = {
  id: number
  kind: 'confirm' | 'notify'
  title: string
  message: string
  confirmLabel: string
  cancelLabel?: string
  tone: DialogTone
  resolve: (accepted: boolean) => void
}

type DialogApi = {
  confirm: (options: ConfirmOptions) => Promise<boolean>
  notify: (options: NotifyOptions) => Promise<void>
}

const DialogContext = createContext<DialogApi | null>(null)
let nextDialogId = 1

const iconForTone = (tone: DialogTone) => {
  if (tone === 'success') return '✓'
  if (tone === 'warning') return '!'
  if (tone === 'danger') return '×'
  return 'i'
}

export function AppDialogProvider({ children }: { children: ReactNode }) {
  const [queue, setQueue] = useState<DialogRequest[]>([])
  const active = queue[0] || null

  const enqueue = useCallback((request: Omit<DialogRequest, 'id'>) => {
    const dialog = { ...request, id: nextDialogId++ }
    setQueue(current => [...current, dialog])
  }, [])

  const confirm = useCallback((options: ConfirmOptions) => new Promise<boolean>(resolve => {
    enqueue({
      kind: 'confirm',
      title: options.title,
      message: options.message,
      confirmLabel: options.confirmLabel || 'Confirm',
      cancelLabel: options.cancelLabel || 'Cancel',
      tone: options.tone || 'warning',
      resolve,
    })
  }), [enqueue])

  const notify = useCallback((options: NotifyOptions) => new Promise<void>(resolve => {
    enqueue({
      kind: 'notify',
      title: options.title,
      message: options.message,
      confirmLabel: options.buttonLabel || 'OK',
      tone: options.tone || 'info',
      resolve: () => resolve(),
    })
  }), [enqueue])

  const close = useCallback((accepted: boolean) => {
    setQueue(current => {
      const [first, ...rest] = current
      if (first) queueMicrotask(() => first.resolve(accepted))
      return rest
    })
  }, [])

  useEffect(() => {
    if (!active) return
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.preventDefault()
      close(active.kind === 'notify')
    }
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [active, close])

  const value = useMemo(() => ({ confirm, notify }), [confirm, notify])

  return <DialogContext.Provider value={value}>
    {children}
    {active && <div className="appDialogBackdrop" role="presentation">
      <div
        className={'appDialogCard ' + active.tone}
        role={active.kind === 'confirm' ? 'alertdialog' : 'dialog'}
        aria-modal="true"
        aria-labelledby={'app-dialog-title-' + active.id}
        aria-describedby={'app-dialog-message-' + active.id}
      >
        <div className={'appDialogIcon ' + active.tone}>{iconForTone(active.tone)}</div>
        <div className="appDialogContent">
          <h2 id={'app-dialog-title-' + active.id}>{active.title}</h2>
          <p id={'app-dialog-message-' + active.id}>{active.message}</p>
        </div>
        <div className="appDialogActions">
          {active.kind === 'confirm' && <button
            className="secondary"
            type="button"
            onClick={() => close(false)}
          >{active.cancelLabel}</button>}
          <button
            className={active.tone === 'danger' ? 'appDialogDangerButton' : 'primary'}
            type="button"
            autoFocus
            onClick={() => close(true)}
          >{active.confirmLabel}</button>
        </div>
      </div>
    </div>}
  </DialogContext.Provider>
}

export function useAppDialog() {
  const context = useContext(DialogContext)
  if (!context) throw new Error('useAppDialog must be used within AppDialogProvider')
  return context
}
