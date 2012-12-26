#include "blowfish.h"

Blowfish::Blowfish(const BlowfishKey &key)
{
    setKey(key);
}

void Blowfish::setKey(const BlowfishKey &key)
{
    initializeContext(key);
}

quint64 Blowfish::encrypt(quint64 data)
{
    QPair<quint32, quint32> pair = split(data);
    encrypt(pair.first, pair.second);
    return join(pair.first, pair.second);
}

quint64 Blowfish::decrypt(quint64 data)
{
    QPair<quint32, quint32> pair = split(data);
    decrypt(pair.first, pair.second);
    return join(pair.first, pair.second);
}

void Blowfish::encrypt(quint32 &left, quint32 &right)
{
    for (int i = 0; i < 16; ++i) {
        left = left ^ m_pArray[i];
        right = function(left) ^ right;
        swap(left, right);
    }

    swap(left, right);

    right = right ^ m_pArray[16];
    left = left ^ m_pArray[17];
}

void Blowfish::decrypt(quint32 &left, quint32 &right)
{
    for (int i = 17; i > 1; --i) {
        left = left ^ m_pArray[i];
        right = function(left) ^ right;
        swap(left, right);
    }

    swap(left, right);

    right = right ^ m_pArray[1];
    left = left ^ m_pArray[0];
}

quint32 Blowfish::function(quint32 data)
{
    // Divide data into bytes a, b, c, d.
    // Now function(data) = ((((S1[a] + S2[b]) mod 2**32)
    //                      xor S3(c)) + s4(d)) mode 2**32.

    quint8 d = (quint8)data;
    data >>= 8;

    quint8 c = (quint8)data;
    data >>= 8;

    quint8 b = (quint8)data;
    data >>= 8;

    quint8 a = (quint8)data;

    quint32 result = m_sBoxes[0][a] + m_sBoxes[1][b]; // quint32 will be xor'ed
                                                      // to 2**32 by compiler
    result ^= m_sBoxes[2][c];
    result += m_sBoxes[3][d];

    return result;
}

void Blowfish::initializeContext(const BlowfishKey &key)
{

    // Copy initial values to context
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 256; ++j) {
            m_sBoxes[i][j] = S_BOXES_INITIAL[i][j];
        }
    }

    // XOR initial P-array with key and save result to context
    int j = 0;
    for (int i = 0; i < 18; ++i) {
        quint32 data = 0;

        // XOR data with four bytes from key
        for (int k = 0; k < 4; ++k) {
            data = (data << 8) | key[j];
            j = (j + 1) % BLOWFISH_KEY_SIZE_IN_BYTES;
        }

        m_pArray[i] = P_ARRAY_INITIAL[i] ^ data;
    }


    // Encrypt all-zero data consequently and writing output
    // to context

    quint32 dataLeft = 0;
    quint32 dataRight = 0;

    // Process P-array
    for (int i = 0; i < 18; i += 2) {
        encrypt(dataLeft, dataRight);
        m_pArray[i] = dataLeft;
        m_pArray[i + 1] = dataRight;
    }

    // Process S-boxes
    for (int i = 0; i < 4; ++i) {
        for (int j = 0; j < 256; j += 2) {
            encrypt(dataLeft, dataRight);
            m_sBoxes[i][j] = dataLeft;
            m_sBoxes[i][j + 1] = dataRight;
        }
    }

}

void Blowfish::swap(quint32 &left, quint32 &right)
{
    quint32 oldLeft = left;
    left = right;
    right = oldLeft;
}

QPair<quint32, quint32> Blowfish::split(quint64 value)
{
    QPair<quint32, quint32> result;

    result.second = (quint32)value;
    value >>= 32;
    result.first = (quint32)value;

    return result;
}

quint64 Blowfish::join(quint32 left, quint32 right)
{
    quint64 result = left;
    result <<= 32;
    result += right;

    return result;
}
