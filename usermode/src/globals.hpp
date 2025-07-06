#pragma once
namespace globals {
	// screen width and height
	inline int width = GetSystemMetrics(SM_CXSCREEN);
	inline int height = GetSystemMetrics(SM_CYSCREEN);
	inline int screen_center_x = width / 2;
	inline int screen_center_y = height / 2;
	// dont write to memory unless disabled
	inline bool safe_mode = false;
}