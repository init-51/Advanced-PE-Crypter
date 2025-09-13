#pragma once

__forceinline void morphcode(char* a) {

    volatile int _morph_var = a;

    if (_morph_var % 3) {
        _morph_var += (int)a + 2;
        while (!(_morph_var % 4)) ++_morph_var;
    }
    else if (_morph_var % 2) {
        _morph_var -= (int)a - 2;
        while (!(_morph_var % 3)) ++_morph_var;
    }
    else if (_morph_var % 5) {
        _morph_var = (_morph_var + 11) / ((int)a + 23);
        while (!(_morph_var % 3))
            if (_morph_var % 5)
                ++_morph_var;
            else --_morph_var;
    }
}