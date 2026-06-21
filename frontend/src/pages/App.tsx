import { useState } from "react";
import VulnerabilitiesPage from "../VulnerabilitiesPage";
import "./App.css";
import { Dashboard } from "./Dashboard";

function App() {
  const [input, setInput] = useState("");
  const [projectId, setProjectId] = useState("");

  return <Dashboard />;
}

export default App;
