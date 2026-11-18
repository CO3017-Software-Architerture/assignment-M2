#pragma once

#include "IFacade.hpp"

class Barrier : public IBarrier
{
private:
    bool m_isOpen{false};

public:
    Barrier() : m_isOpen(false) {}
    ~Barrier() override = default;

    void OpenGate() override { m_isOpen = true; }
    void CloseGate() override { m_isOpen = false; }
    bool isOpen() const override { return m_isOpen; }
};