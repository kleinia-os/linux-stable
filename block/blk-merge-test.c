// SPDX-License-Identifier: GPL-2.0
#include <kunit/test.h>
#include <linux/bio.h>
#include <linux/blk-mq.h>
#include <linux/blkdev.h>
#include <linux/sched.h>

#include "blk.h"
#include "elevator.h"

static void blk_attempt_plug_merge_rejects_tail_bypass_mismatch(struct kunit *test)
{
	struct elevator_queue *elevator;
	struct request_queue *queue;
	struct request rq = { };
	struct bio bio = { };
	struct blk_plug plug;

	elevator = kunit_kzalloc(test, sizeof(*elevator), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, elevator);
	queue = kunit_kzalloc(test, sizeof(*queue), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, queue);
	queue->elevator = elevator;
	rq.q = queue;
	rq.rq_flags = RQF_USE_SCHED;

	blk_start_plug(&plug);
	rq_list_add_tail(&plug.mq_list, &rq);
	KUNIT_EXPECT_FALSE(test, blk_attempt_plug_merge(queue, &bio, 0, true));
	current->plug = NULL;
}

static void blk_attempt_plug_merge_skips_bypass_mismatch(struct kunit *test)
{
	struct elevator_queue *elevator;
	struct request_queue *other_queue;
	struct request_queue *queue;
	struct request other_rq = { };
	struct request rq = { };
	struct bio bio = { };
	struct blk_plug plug;

	elevator = kunit_kzalloc(test, sizeof(*elevator), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, elevator);
	queue = kunit_kzalloc(test, sizeof(*queue), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, queue);
	other_queue = kunit_kzalloc(test, sizeof(*other_queue), GFP_KERNEL);
	KUNIT_ASSERT_NOT_NULL(test, other_queue);
	queue->elevator = elevator;
	other_rq.q = other_queue;
	rq.q = queue;
	rq.rq_flags = RQF_USE_SCHED;

	blk_start_plug(&plug);
	rq_list_add_tail(&plug.mq_list, &rq);
	rq_list_add_tail(&plug.mq_list, &other_rq);
	plug.multiple_queues = true;
	KUNIT_EXPECT_FALSE(test, blk_attempt_plug_merge(queue, &bio, 0, true));
	current->plug = NULL;
}

static struct kunit_case blk_merge_test_cases[] = {
	KUNIT_CASE(blk_attempt_plug_merge_rejects_tail_bypass_mismatch),
	KUNIT_CASE(blk_attempt_plug_merge_skips_bypass_mismatch),
	{}
};

static struct kunit_suite blk_merge_test_suite = {
	.name = "blk_merge",
	.test_cases = blk_merge_test_cases,
};

kunit_test_suite(blk_merge_test_suite);
