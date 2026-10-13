"""Git in a test: a repository of its own, never the one the tests run in."""

# What tells git where its repository is. A test run from a hook of git has them set to the real
# repository, and a test that makes a repository and commits to it must not meet that one.
WHERE_GIT_LOOKS = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_NAMESPACE",
    "GIT_PREFIX",
)
