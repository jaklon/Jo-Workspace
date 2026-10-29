import type { JSX } from 'react'
import logo from '../assets/jo-workspace-logo.jpg'

export function BrandMark({ large = false }: { large?: boolean }): JSX.Element {
  return (
    <span
      className={`jo-brand-mark${large ? ' jo-brand-large' : ''}`}
      role="img"
      aria-label="Logo Jo Workspace"
    >
      <img src={logo} alt="" draggable={false} />
    </span>
  )
}
