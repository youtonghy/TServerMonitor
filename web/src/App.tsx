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
  tasks: lazy(() => import('@/pages/tasks')),
  settings: lazy(() => import('@/pages/settings')),
  alerts: lazy(() => import('@/pages/alerts')),
  packages: lazy(() => import('@/pages/packages')),
}

const Wall = lazy(() => import('@/pages/wall'))

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
  const route = useRoute()
  // the wallboard is full-screen, without the navigation shell
  if (route.segments[0] === 'wall') {
    return (
      <LiveProvider>
        <Suspense fallback={<Skeleton lines={8} label="正在加载大屏" />}>
          <Wall />
        </Suspense>
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
