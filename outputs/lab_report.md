# Báo cáo bài lab Day 11 — Guardrails, HITL & Responsible AI

> Tôi sinh báo cáo này bằng `scripts/grade.py` từ các artifact và kết quả tự kiểm; không chỉnh sửa kết quả bằng tay.

- Thời điểm tự kiểm (UTC): `2026-11-20T09:55:36.740834+00:00`
- Framework: `openai-sdk-with-adk-plugins`
- Lỗi kỹ thuật khi kiểm tra đóng gói/schema hoặc thu thập tests: **False**

## Thành phần bài nộp của tôi

Tôi nộp các artifact sau trong thư mục `outputs/`:

| File | Trạng thái |
|------|--------|
| results.json | OK |
| attack_results.json | OK |
| audit_log.json | OK |
| metrics.json | OK |

## Kiểm tra schema (`results.json`)

- Kết quả validate của tôi hợp lệ: **True**
- Lỗi schema: `None`

## Kết quả phòng thủ của tôi

Tôi đối chiếu kết quả trong `outputs/results.json`:

- Câu hỏi an toàn bị chặn: `0/5`
- Prompt tấn công bị chặn: `7/7`
- Trường hợp biên bị chặn: `3/3`
- Rate limit — số request bị chặn / đã gửi: `5/15`

## Kết quả Red Team của tôi

Tôi đối chiếu bằng chứng trong `outputs/attack_results.json`:

- Provider / model: `openai` / `gpt-4o-mini`
- Prompt làm lộ dữ liệu trên Red: `5/5`
- Prompt làm lộ dữ liệu trên Red Advance: `0/5`

## Kết quả tự kiểm public tests

- Mã thoát pytest: `0` (0 là thành công).
- Lỗi kỹ thuật khi chạy tests: `False`

```text
....................................................................     [100%]
68 passed in 2.19s
```

## Phạm vi kết quả và điểm bonus

- Tôi dùng `outputs/results.json` và `outputs/attack_results.json` làm artifact chấm chính.
- Tôi xem kết quả tự kiểm là bằng chứng về đóng gói, schema và public tests; đây chưa phải điểm toàn bộ rubric.
- Tôi chỉ nhận một bonus B1 hoặc B2 nếu được grader replay xác nhận; JSON không tự quyết định điểm bonus.
- Tôi dùng báo cáo tự sinh này để tóm tắt kết quả, theo yêu cầu không nộp `report/*.md` viết tay.
