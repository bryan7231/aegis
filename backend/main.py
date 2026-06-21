from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from models import Project, ProjectCreate
from datetime import datetime

app = FastAPI(title="Aegis Backend", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

projects_db: dict[str, Project] = {}


@app.get("/")
def read_root():
    return {"message": "Aegis Backend API"}


@app.post("/projects", response_model=Project)
def create_project(project_data: ProjectCreate):
    """Create a new project"""
    project = Project(
        name=project_data.name,
        description=project_data.description,
    )
    projects_db[project.id] = project
    return project


@app.get("/projects", response_model=list[Project])
def get_projects():
    """Get all previous projects"""
    return list(projects_db.values())


@app.get("/projects/{project_id}", response_model=Project)
def get_project(project_id: str):
    """Get a specific project by ID"""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    return projects_db[project_id]


@app.put("/projects/{project_id}", response_model=Project)
def update_project(project_id: str, project_data: ProjectCreate):
    """Update a project"""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")

    project = projects_db[project_id]
    project.name = project_data.name
    project.description = project_data.description
    project.updated_at = datetime.utcnow()
    projects_db[project_id] = project
    return project


@app.delete("/projects/{project_id}")
def delete_project(project_id: str):
    """Delete a project"""
    if project_id not in projects_db:
        raise HTTPException(status_code=404, detail="Project not found")
    del projects_db[project_id]
    return {"message": "Project deleted successfully"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
