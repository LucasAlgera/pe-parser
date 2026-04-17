#include "pe.h"
#include <vector>

class RenderImGui
{
public:
	RenderImGui(PE64* _PE);
	void RenderTick();
private:
	PE64* PE;
	int currentAdress = 0;

	void RenderMenuBar();
	void RenderSideBar();
	void RenderInfo();
	void RenderBinary();
	void RenderHex();

	const int rows = 32;
	struct Data
	{
		BYTE data[32 * 16];
	};
	Data* data = nullptr;
};