#ifndef BARRIER_HPP
#define BARRIER_HPP

class Barrier
{
private:
    bool m_isOpen{false};

public:
    Barrier() : m_isOpen(false) {}
    ~Barrier() = default;

    // TODO add console logging 
    void OpenGate() { m_isOpen = true; }
    void CloseGate() { m_isOpen = false; }
    bool isOpen() const { return m_isOpen; }
};

#endif
