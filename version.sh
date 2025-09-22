#!/bin/bash

# Version management script for PubliKey Agent

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_GO="$SCRIPT_DIR/main.go"

# Function to get current version
get_current_version() {
    grep -E '^\s*Version\s*=' "$MAIN_GO" | sed 's/.*Version.*=.*"\([^"]*\)".*/\1/'
}

# Function to set new version
set_version() {
    local new_version="$1"
    if [[ ! "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Version must be in format X.Y.Z (e.g., 1.0.0)"
        exit 1
    fi

    sed -i.bak "s/Version[[:space:]]*=[[:space:]]*\"[^\"]*\"/Version   = \"$new_version\"/" "$MAIN_GO"
    rm "$MAIN_GO.bak"
    echo "Updated version to $new_version"
}

# Function to bump version
bump_version() {
    local bump_type="$1"
    local current_version
    current_version=$(get_current_version)

    IFS='.' read -r major minor patch <<< "$current_version"

    case "$bump_type" in
        major)
            major=$((major + 1))
            minor=0
            patch=0
            ;;
        minor)
            minor=$((minor + 1))
            patch=0
            ;;
        patch)
            patch=$((patch + 1))
            ;;
        *)
            echo "Error: Bump type must be 'major', 'minor', or 'patch'"
            exit 1
            ;;
    esac

    local new_version="$major.$minor.$patch"
    set_version "$new_version"
}

# Main script logic
case "${1:-}" in
    get)
        get_current_version
        ;;
    set)
        if [[ -z "$2" ]]; then
            echo "Error: Please provide a version number"
            echo "Usage: $0 set X.Y.Z"
            exit 1
        fi
        set_version "$2"
        ;;
    bump)
        if [[ -z "$2" ]]; then
            echo "Error: Please provide bump type (major, minor, patch)"
            echo "Usage: $0 bump [major|minor|patch]"
            exit 1
        fi
        bump_version "$2"
        ;;
    *)
        echo "PubliKey Agent Version Management"
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  get                 Show current version"
        echo "  set X.Y.Z          Set specific version"
        echo "  bump [type]        Bump version (major, minor, or patch)"
        echo ""
        echo "Examples:"
        echo "  $0 get"
        echo "  $0 set 1.2.3"
        echo "  $0 bump patch"
        echo "  $0 bump minor"
        echo "  $0 bump major"
        echo ""
        echo "Current version: $(get_current_version)"
        ;;
esac