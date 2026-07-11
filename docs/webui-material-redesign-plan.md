# WebUI Google / Material 风格优化说明

日期：2026-07-09

## 设计定位

Monitor WebUI 是运维控制台，不是营销官网。界面应接近 Google Cloud Console / Firebase Console 的工作台气质：安静、清晰、可扫描、信息密度适中，避免大面积渐变、夸张卡片、装饰性图形和过度圆角。

## 视觉原则

- 颜色：白底、浅灰页面背景、Google Blue 主色；红/黄/绿只表达状态。
- 层级：用细边框、轻阴影、间距和字体大小建立层级，不依赖厚重卡片。
- 圆角：工具面板和输入控件控制在 8-12px，状态 chip 保持胶囊形。
- 字体：系统无衬线字体，标题克制，表格和控制区保持紧凑。
- 交互：按钮、输入框、表格行、节点卡片都要有清晰 hover/focus 状态。
- 控制台感：保留左侧导航、顶部操作区、资源列表、详情区和活动日志的布局。

## 本次改造范围

- 不引入 Vue 或新前端框架。
- 不改变 API、WebSocket 协议和业务状态结构。
- 主要调整 `web/index.html` 的信息文案密度和 `web/styles.css` 的 Material 视觉层级。
- 保留现有功能：登录、Dashboard、节点卡片、图表、告警、容器、命令、审计、深色模式和图表缩放。

## 后续建议

如果继续增强前端，优先顺序应为：

1. 拆分 `web/app.js` 为 api/auth/ws/render/commands/utils 等模块。
2. 增加 Playwright smoke test，覆盖登录、图表、容器操作确认和审计导出。
3. 做设置页、用户管理、Agent token 管理时，再评估 Vue。

