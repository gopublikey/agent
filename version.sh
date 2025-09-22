#!/bin/bash

# Version management script for PubliKey Agent

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MAIN_GO="$SCRIPT_DIR/main.go"

# Function to get current version
get_current_version() {
    grep -E '^\s*Version\s*=' "$MAIN_GO" | sed 's/.*Version.*=.*"\([^"]*\)".*/\1/'
}

# Function to tag and push git version
git_tag_and_push() {
    local version="$1"
    local tag="v$version"

    echo "Committing version change..."
    git add "$MAIN_GO"
    git commit -m "chore: bump version to $version"

    echo "Creating and pushing tag $tag..."
    git tag "$tag"
    git push origin main
    git push origin "$tag"

    echo "Successfully tagged and pushed $tag"
}

# Function to set new version
set_version() {
    local new_version="$1"
    local tag_and_push="${2:-false}"
    if [[ ! "$new_version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        echo "Error: Version must be in format X.Y.Z (e.g., 1.0.0)"
        exit 1
    fi

    sed -i.bak "s/Version[[:space:]]*=[[:space:]]*\"[^\"]*\"/Version   = \"$new_version\"/" "$MAIN_GO"
    rm "$MAIN_GO.bak"
    echo "Updated version to $new_version"

    if [[ "$tag_and_push" == "true" ]]; then
        git_tag_and_push "$new_version"
    fi
}

# Function to bump version
bump_version() {
    local bump_type="$1"
    local tag_and_push="${2:-false}"
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
    set_version "$new_version" "$tag_and_push"
}

# Main script logic
case "${1:-}" in
    get)
        get_current_version
        ;;
    set)
        if [[ -z "$2" ]]; then
            echo "Error: Please provide a version number"
            echo "Usage: $0 set X.Y.Z [--tag]"
            exit 1
        fi
        tag_flag="false"
        if [[ "$3" == "--tag" ]]; then
            tag_flag="true"
        fi
        set_version "$2" "$tag_flag"
        ;;
    bump)
        if [[ -z "$2" ]]; then
            echo "Error: Please provide bump type (major, minor, patch)"
            echo "Usage: $0 bump [major|minor|patch] [--tag]"
            exit 1
        fi
        tag_flag="false"
        if [[ "$3" == "--tag" ]]; then
            tag_flag="true"
        fi
        bump_version "$2" "$tag_flag"
        ;;
    tag)
        current_version=$(get_current_version)
        git_tag_and_push "$current_version"
        ;;
    *)
        echo "PubliKey Agent Version Management"
        echo ""
        echo "Usage: $0 [command] [options]"
        echo ""
        echo "Commands:"
        echo "  get                 Show current version"
        echo "  set X.Y.Z [--tag]  Set specific version (optionally tag and push)"
        echo "  bump [type] [--tag] Bump version (major, minor, or patch, optionally tag and push)"
        echo "  tag                 Tag and push current version"
        echo ""
        echo "Examples:"
        echo "  $0 get"
        echo "  $0 set 1.2.3"
        echo "  $0 set 1.2.3 --tag"
        echo "  $0 bump patch"
        echo "  $0 bump patch --tag"
        echo "  $0 bump minor --tag"
        echo "  $0 tag"
        echo ""
        echo "Current version: $(get_current_version)"
        ;;
esac