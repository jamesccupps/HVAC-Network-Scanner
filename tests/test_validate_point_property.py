"""Tests for bacnet._validate_point_property.

This validator is the second line of defense (behind invoke-id filtering) against
values ending up in the wrong column of the Points tab. For each property name,
we have an expectation about what type the value should be, and anything that
doesn't match gets dropped.
"""

import pytest

from hvac_scanner.bacnet import _validate_point_property


class TestPresentValue:
    """presentValue can be numeric (analog), enum (binary/MS), or string."""

    def test_float_kept(self):
        assert _validate_point_property('presentValue', 72.5) == 72.5

    def test_int_kept(self):
        # Enum value from binary/MS point
        assert _validate_point_property('presentValue', 3) == 3

    def test_bool_kept(self):
        # Binary points may come back as bool
        assert _validate_point_property('presentValue', True) is True

    def test_string_kept(self):
        # Some devices return stateText as present value
        assert _validate_point_property('presentValue', 'Occupied') == 'Occupied'

    def test_list_dropped(self):
        """A list value indicates multi-value — drop rather than show '[2 values]' in PV column."""
        assert _validate_point_property('presentValue', [70.5, 0.0]) is None

    def test_none_dropped(self):
        assert _validate_point_property('presentValue', None) is None


class TestObjectName:
    """objectName must be a string. Floats/ints mean packet misalignment."""

    def test_string_kept(self):
        assert _validate_point_property('objectName', 'Space Temp') == 'Space Temp'

    def test_float_dropped(self):
        """Regression: Trane Tracer observed emitting float where name expected.

        Previous version str()'d the float — producing names like '70.501953125'
        in the Name column. Now dropped outright.
        """
        assert _validate_point_property('objectName', 70.501953125) is None

    def test_int_dropped(self):
        assert _validate_point_property('objectName', 64) is None

    def test_list_dropped(self):
        assert _validate_point_property('objectName', ['a', 'b']) is None


class TestUnits:
    """units normally int enum; some devices override with custom string."""

    def test_int_kept(self):
        assert _validate_point_property('units', 64) == 64

    def test_string_kept(self):
        """Trane sometimes emits custom unit strings like 'deg F'."""
        assert _validate_point_property('units', 'deg F') == 'deg F'

    def test_float_dropped(self):
        """A float where an int enum was expected = misalignment."""
        assert _validate_point_property('units', 64.0) is None

    def test_bool_dropped(self):
        """Bool is a Python int subclass but makes no semantic sense for units."""
        assert _validate_point_property('units', True) is None
        assert _validate_point_property('units', False) is None


class TestDescription:
    """description must be a string."""

    def test_string_kept(self):
        assert _validate_point_property('description', 'Zone sensor') == 'Zone sensor'

    def test_empty_string_kept(self):
        assert _validate_point_property('description', '') == ''

    def test_numeric_dropped(self):
        assert _validate_point_property('description', 42) is None
        assert _validate_point_property('description', 3.14) is None


class TestUnknownProperty:
    """Unknown property names fall through to 'any' expectation."""

    def test_passthrough(self):
        assert _validate_point_property('weirdProp', 'whatever') == 'whatever'
        assert _validate_point_property('weirdProp', 42) == 42
