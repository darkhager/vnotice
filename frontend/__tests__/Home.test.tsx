import '@testing-library/jest-dom'
import { render } from '@testing-library/react'
import Home from '../src/app/page'

describe('Home Page', () => {
  it('renders the main element', () => {
    const { container } = render(<Home />)
    const main = container.querySelector('main')
    expect(main).toBeInTheDocument()
  })
})
