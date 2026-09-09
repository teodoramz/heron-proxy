import { useCallback, useEffect, useState } from 'react'

type Theme = 'dark' | 'light'

/** useTheme persists the viewer's choice; the default follows the system. */
export function useTheme(): [Theme, () => void] {
  const [theme, setTheme] = useState<Theme>(() => {
    const stored = localStorage.getItem('pw-theme')
    if (stored === 'dark' || stored === 'light') return stored
    return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark'
  })

  useEffect(() => {
    document.documentElement.setAttribute('data-theme', theme)
    localStorage.setItem('pw-theme', theme)
  }, [theme])

  const toggle = useCallback(() => setTheme((t) => (t === 'dark' ? 'light' : 'dark')), [])
  return [theme, toggle]
}
