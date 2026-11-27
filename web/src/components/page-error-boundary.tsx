import { Component, type ErrorInfo, type ReactNode } from 'react'
import { Button } from '@/components/arc/button/button'
import { EmptyState } from '@/components/arc/empty-state/empty-state'

interface Props {
  children: ReactNode
}

interface State {
  error: Error | null
}

/**
 * Catches a page that failed to load or render, so the navigation stays usable instead of a blank
 * screen. The usual cause is a lazy page chunk that could not be fetched (network hiccup, or an old
 * tab after an upgrade replaced the chunk hashes). `lazy()` caches the failed import, so recovery
 * needs a full reload. Give it a `key` per route so moving to another page clears the error.
 */
export class PageErrorBoundary extends Component<Props, State> {
  state: State = { error: null }

  static getDerivedStateFromError(error: Error): State {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('page failed', error, info.componentStack)
  }

  render() {
    if (!this.state.error) return this.props.children
    return (
      <EmptyState
        title="页面加载失败"
        description="网络中断或面板刚升级过，重新加载即可。"
        action={<Button onClick={() => window.location.reload()}>重新加载</Button>}
      />
    )
  }
}
