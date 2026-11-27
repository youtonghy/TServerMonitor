import { lazy, Suspense, useCallback, useEffect, useMemo, useState, type ComponentType } from 'react'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { LiveProvider } from '@/api/live'
import { api, notifyAuthChange, onUnauthorized } from '@/api/client'
import type { AuthState } from '@/api/types'
import { AuthContext } from '@/components/auth-context'
import { SudoDialog } from '@/components/sudo-dialog'
import LoginPage from '@/pages/login'
import SetupPage from '@/pages/setup'
import { AppShell } from '@/components/app-shell'
import { NotFound } from '@/pages/not-found'
import { PageErrorBoundary } from '@/components/page-error-boundary'
import { useRoute } from '@/lib/router'

const pages: Record<string, ComponentType> = {
  '': lazy(() => import('@/pages/overview')),
  trends: lazy(() => import('@/pages/trends')),
  containers: lazy(() => import('@/pages/containers')),
  logs: lazy(() => import('@/pages/logs')),
  security: lazy(() => import('@/pages/security')),
  reports: lazy(() => import('@/pages/reports')),
  agent: lazy(() => import('@/pages/agent')),
  tasks: lazy(() => import('@/pages/tasks')),
  settings: lazy(() => import('@/pages/settings')),
  alerts: lazy(() => import('@/pages/alerts')),
  packages: lazy(() => import('@/pages/packages')),
  nginx: lazy(() => import('@/pages/nginx')),
  firewall: lazy(() => import('@/pages/firewall')),
  ssh: lazy(() => import('@/pages/ssh')),
  ops: lazy(() => import('@/pages/ops-log')),
}

const Wall = lazy(() => import('@/pages/wall'))

function Router() {
  const route = useRoute()
  const segment = route.segments[0] ?? ''
  const Page = pages[segment] ?? NotFound
  return (
    <PageErrorBoundary key={segment}>
      <Suspense fallback={<Skeleton lines={8} label="正在加载页面" />}>
        <Page />
      </Suspense>
    </PageErrorBoundary>
  )
}

const SIGNED_OUT: AuthState = { setup_required: false, authenticated: false, kind: null, user: null, sudo_until: 0 }

/** Setup wizard on first start, then the sign-in page, then the dashboard. */
export default function App() {
  const [auth, setAuth] = useState<AuthState | null>(null)
  const [expired, setExpired] = useState(false)

  const load = useCallback(() => api.authState().then(setAuth, () => setAuth(SIGNED_OUT)), [])
  useEffect(() => {
    void load()
  }, [load])
  useEffect(() => onUnauthorized(code => {
    setExpired(code === 'login_required')
    void load()
  }), [load])

  const signedIn = useCallback(() => {
    setExpired(false)
    void load().then(notifyAuthChange)
  }, [load])
  const logout = useCallback(() => {
    void api.logout().catch(() => undefined).finally(() => {
      setExpired(false)
      void load()
    })
  }, [load])
  const info = useMemo(() => ({ user: auth?.user ?? null, logout }), [auth, logout])

  if (!auth) return <Skeleton lines={8} label="正在加载" />
  if (auth.setup_required) return <SetupPage onDone={signedIn} />
  if (!auth.authenticated) return <LoginPage onDone={signedIn} expired={expired} />
  return (
    <AuthContext.Provider value={info}>
      <Dashboard />
      <SudoDialog />
    </AuthContext.Provider>
  )
}

function Dashboard() {
  const route = useRoute()
  // the wallboard is full-screen, without the navigation shell
  if (route.segments[0] === 'wall') {
    return (
      <LiveProvider>
        <PageErrorBoundary>
          <Suspense fallback={<Skeleton lines={8} label="正在加载大屏" />}>
            <Wall />
          </Suspense>
        </PageErrorBoundary>
      </LiveProvider>
    )
  }
  return (
    <LiveProvider>
      <AppShell>
        <Router />
      </AppShell>
    </LiveProvider>
  )
}
