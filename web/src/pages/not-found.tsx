import { EmptyState } from '@/components/arc/empty-state/empty-state'
import { Link } from '@/lib/router'

export function NotFound() {
  return (
    <EmptyState
      title="页面不存在"
      description="地址可能有误，或该页面已移动。"
      action={<Link to="/">返回总览</Link>}
    />
  )
}
