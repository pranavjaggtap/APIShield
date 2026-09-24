package com.apishield.risk.context;

/**
 * Marker for one type of contextual data the risk engine can take into account (for example,
 * route sensitivity or client history). Each type is an immutable value obtained before scoring,
 * so the engine itself never performs I/O. No implementations exist yet.
 */
public interface ContextualInput {
}
