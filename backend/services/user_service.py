"""Account deletion that also removes the data pointing at the account."""

from sqlalchemy.orm import Session, Query

from ..models import (
    ApiToken,
    Bookmark,
    Comment,
    CommentVote,
    CVEVote,
    EmailVerification,
    Notification,
    NotificationDelivery,
    NotificationSetting,
    User,
    UserRole,
    WatchedProduct,
)


def active_admins_query(db: Session) -> Query:
    """All active administrators, in a fixed order, locked for the transaction."""
    return (
        db.query(User.id)
        .filter(User.role == UserRole.ADMIN, User.is_active.is_(True))
        .order_by(User.id)
        .with_for_update()
    )


def other_active_admins(db: Session, exclude_id: int) -> int:
    """
    How many active administrators besides ``exclude_id`` exist, with all active
    administrator rows locked (``SELECT ... FOR UPDATE``) until commit.

    "Is there another admin?" followed by "now remove this one" is a
    check-then-act sequence. Without the lock two administrators who remove
    each other at the same moment both see "the other one still exists" and
    both succeed: the system is left without an administrator. With the lock
    the second request waits, then re-reads the committed state and is refused.
    The fixed ``ORDER BY id`` makes concurrent requests take the locks in the
    same order, so they queue instead of deadlocking.
    """
    return sum(1 for (admin_id,) in active_admins_query(db).all() if admin_id != exclude_id)


def _comment_tree_ids(db: Session, user_id: int) -> list:
    """Ids of all comments of the user plus every reply below them."""
    ids = [row[0] for row in db.query(Comment.id).filter(Comment.user_id == user_id).all()]
    seen = set(ids)
    frontier = list(ids)
    while frontier:
        children = [
            row[0]
            for row in db.query(Comment.id).filter(Comment.parent_id.in_(frontier)).all()
            if row[0] not in seen
        ]
        seen.update(children)
        frontier = children
    return list(seen)


def delete_user_and_data(db: Session, user: User) -> None:
    """
    Delete the account. The database has no cascading rules for most tables, so
    the dependent rows are removed here first (otherwise PostgreSQL refuses the
    delete). Tech stacks are removed by the database (ON DELETE CASCADE).

    Removed: bookmarks, votes, notifications received, the user's comments
    including replies below them. Kept but detached: notifications the user
    triggered for others, e-mail verification records.
    """
    comment_ids = _comment_tree_ids(db, user.id)
    if comment_ids:
        db.query(CommentVote).filter(CommentVote.comment_id.in_(comment_ids)).delete(
            synchronize_session=False
        )
        # replies first: break the parent links, then delete
        db.query(Comment).filter(Comment.id.in_(comment_ids)).update(
            {Comment.parent_id: None}, synchronize_session=False
        )
        db.query(Comment).filter(Comment.id.in_(comment_ids)).delete(synchronize_session=False)

    db.query(CommentVote).filter(CommentVote.user_id == user.id).delete(synchronize_session=False)
    db.query(CVEVote).filter(CVEVote.user_id == user.id).delete(synchronize_session=False)
    db.query(Bookmark).filter(Bookmark.user_id == user.id).delete(synchronize_session=False)
    db.query(WatchedProduct).filter(WatchedProduct.user_id == user.id).delete(
        synchronize_session=False
    )
    db.query(NotificationDelivery).filter(NotificationDelivery.user_id == user.id).delete(
        synchronize_session=False
    )
    db.query(NotificationSetting).filter(NotificationSetting.user_id == user.id).delete(
        synchronize_session=False
    )
    db.query(ApiToken).filter(ApiToken.user_id == user.id).delete(synchronize_session=False)
    db.query(Notification).filter(Notification.user_id == user.id).delete(synchronize_session=False)
    db.query(Notification).filter(Notification.actor_id == user.id).update(
        {Notification.actor_id: None}, synchronize_session=False
    )
    db.query(EmailVerification).filter(EmailVerification.user_id == user.id).update(
        {EmailVerification.user_id: None}, synchronize_session=False
    )
    db.delete(user)
