Hệ thống honeypot FTP mô phỏng, dùng để thu thập và phân tích hành vi tấn công.

---

## Giới thiệu
Dự án xây dựng một máy chủ FTP giả lập nhằm dụ và ghi lại các hành vi truy cập trái phép. Được xây dựng bằng Python, Flask, Paramiko và Twisted, hệ thống ghi nhận toàn bộ tương tác của kẻ tấn công theo thời gian thực.

## Tính năng
- Mô phỏng phản hồi của một máy chủ FTP thực tế
- Ghi log toàn bộ kết nối, thông tin đăng nhập được thử và lệnh được gửi
- Phát hiện hành vi quét cổng và các công cụ khai thác tự động
- Lưu log có cấu trúc, sẵn sàng để đẩy vào hệ thống SIEM

## Công nghệ sử dụng
`Python` `Flask` `Paramiko` `Twisted` `VMware`

## Cấu trúc log
