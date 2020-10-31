(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const race_selector_component_1 = require("./race-selector.component");
const SELECTOR_RACE_SELECTOR = "#race-center-race-selector";
new race_selector_component_1.RaceSelector(SELECTOR_RACE_SELECTOR);

},{"./race-selector.component":2}],2:[function(require,module,exports){
(function (global){
"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
Object.defineProperty(exports, "__esModule", { value: true });
const $ = (typeof window !== "undefined" ? window['jQuery'] : typeof global !== "undefined" ? global['jQuery'] : null);
const ts_1 = (typeof window !== "undefined" ? window['ndmsRaceCenter'] : typeof global !== "undefined" ? global['ndmsRaceCenter'] : null);
const SELECTOR_PREV_RACE = ".race-previous > a";
const SELECTOR_NEXT_RACE = ".race-next > a";
class RaceSelector extends ts_1.RaceCenterElement {
    constructor(selector) {
        super(selector);
        this._initListeners();
    }
    _initListeners() {
        $(this._selector)
            .on("click", SELECTOR_PREV_RACE, (event) => this._trackClick(event, "Prev race click"))
            .on("click", SELECTOR_NEXT_RACE, (event) => this._trackClick(event, "Next race click"));
    }
    _trackClick(event, text) {
        const target = $(event.currentTarget);
        const link = target.attr("href");
        ts_1.analytics.trackLink(text, link);
    }
    fetch() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    refresh() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    _mount() { }
}
exports.RaceSelector = RaceSelector;

}).call(this,typeof global !== "undefined" ? global : typeof self !== "undefined" ? self : typeof window !== "undefined" ? window : {})
},{}]},{},[1]);
