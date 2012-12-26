#ifndef BLOWFISH_H
#define BLOWFISH_H

#include <QtGlobal>
#include <QPair>

#include "blowfishtables.h"

const int BLOWFISH_KEY_SIZE_IN_BYTES = 56;
typedef quint8 BlowfishKey[BLOWFISH_KEY_SIZE_IN_BYTES];

class Blowfish
{
public:
    Blowfish(const BlowfishKey &key);
    void setKey(const BlowfishKey &key);
    quint64 encrypt(quint64 data);
    quint64 decrypt(quint64 data);

private:
    void encrypt(quint32 &left, quint32 &right);
    void decrypt(quint32 &left, quint32 &right);
    quint32 function(quint32 data);

    void initializeContext(const BlowfishKey &key);

    inline void swap(quint32 &left, quint32 &right);

    QPair<quint32, quint32> split(quint64 value);
    quint64 join(quint32 left, quint32 right);

    // S-boxes and P-array is called context here
    quint32 m_sBoxes[4][256];
    quint32 m_pArray[18];
};

#endif // BLOWFISH_H
