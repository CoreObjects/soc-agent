"""FastAPI 应用工厂 + 前端 dist 静态托管。

生产:`uvicorn soc_agent.web.app:app`(server2 原生,无 nginx → FastAPI 直接托管前端,history 回退)。
测试:`create_app()` 拿干净实例 + dependency_overrides 注入 mock。
"""
import os

__all__ = ["create_app", "app"]


def create_app():
    from fastapi import FastAPI

    app = FastAPI(title="soc-agent 研判处置控制台", version="0.1.0")

    from .routes import alerts, chat, config, experience, plans, stats
    for mod in (alerts, plans, stats, experience, config, chat):
        app.include_router(mod.router)

    @app.get("/api/healthz")
    def healthz():
        return {"ok": True}

    _mount_frontend(app)
    return app


def _mount_frontend(app):
    """有构建产物(soc_agent/frontend/dist)则挂静态 + SPA history 回退;无则跳过(纯 API 模式)。"""
    dist = os.path.join(os.path.dirname(os.path.dirname(__file__)), "frontend", "dist")
    index = os.path.join(dist, "index.html")
    if not os.path.isfile(index):
        return
    from fastapi.responses import FileResponse
    from fastapi.staticfiles import StaticFiles
    app.mount("/assets", StaticFiles(directory=os.path.join(dist, "assets")), name="assets")

    @app.get("/{full_path:path}")
    def spa(full_path: str):
        cand = os.path.join(dist, full_path)
        if full_path and os.path.isfile(cand):
            return FileResponse(cand)
        return FileResponse(index)             # 其余路径回退到 index.html(前端路由接管)


app = create_app()
