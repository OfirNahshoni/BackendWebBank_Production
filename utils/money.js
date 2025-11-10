'use strict';

const mongoose = require('mongoose');

function decimal128ToString(d) {
    if (d == null) return '0.00';

    try {
        return d.toString();
    } catch (_e) {
        return String(d);
    }
}

function decimal128ToNumber(d) {
    const s = decimal128ToString(d);
    const n = Number(s);
    
    return Number.isFinite(n) ? n : 0;
}

function numberToDecimal128(n) {
    const val = Number(n);
    const fixed = Number.isFinite(val) ? val.toFixed(2) : '0.00';

    return mongoose.Schema.Types.Decimal128.fromString(String(fixed));
}

function stringToDecimal128(s) {
    const n = Number(s);

    return numberToDecimal128(Number.isFinite(n) ? n : 0);
}

module.exports = {
    decimal128ToString,
    decimal128ToNumber,
    numberToDecimal128,
    stringToDecimal128,
};
