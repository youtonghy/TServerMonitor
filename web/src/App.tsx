import { lazy, Suspense, type ComponentType } from 'react'
import { Skeleton } from '@/components/arc/skeleton/skeleton'
import { LiveProvider } from '@/api/live'
import { AppShell } from '@/components/app-shell'
import { NotFound } from '@/pages/not-found'
import { useRoute } from '@/lib/router'

const pages: Record<string, ComponentType> = {
  '': lazy(() => import('@/pages/overview')),
  trends: lazy(() => import('@/pages/trends')),
  containers: lazy(() => import('@/pages/containers')),
  logs: lazy(() => import('@/pages/logs')),
  security: lazy(() => import('@/pages/security')),
  reports: lazy(() => import('@/pages/reports')),
  agent: lazy(() => import('@/pages/agent')),
  settings: lazy(() => import('@/pages/settings')),
}

function Router() {
  const route = useRoute()
  const Page = pages[route.segments[0] ?? ''] ?? NotFound
  return (
    <Suspense fallback={<Skeleton lines={8} label="正在加载页面" />}>
      <Page />
    </Suspense>
  )
}

export default function App() {
  return (
    <LiveProvider>
      <AppShell>
        <Router />
      </AppShell>
    </LiveProvider>
  )
}
