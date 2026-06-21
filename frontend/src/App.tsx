import { useState } from 'react'
import VulnerabilitiesPage from './VulnerabilitiesPage'
import './App.css'

function App() {
  const [input, setInput] = useState('')
  const [projectId, setProjectId] = useState('')

  return (
    <div className="app">
      <header className="app-bar">
        <h1 className="app-title">ChainBreak</h1>
        <form
          className="project-picker"
          onSubmit={(e) => {
            e.preventDefault()
            setProjectId(input.trim())
          }}
        >
          <input
            type="text"
            placeholder="Enter project ID…"
            value={input}
            onChange={(e) => setInput(e.target.value)}
          />
          <button type="submit">Load</button>
        </form>
      </header>

      {projectId ? (
        <VulnerabilitiesPage projectId={projectId} />
      ) : (
        <div className="vulns-state">
          Enter a project ID above to view its vulnerabilities.
        </div>
      )}
    </div>
  )
}

export default App
