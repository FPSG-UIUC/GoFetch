#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/cpu.h>
#include <linux/sysfs.h>

#include <asm/cpu.h>

int
is_ecore(void)
{
	uint64_t value;

	asm volatile("mrs %0, mpidr_el1" : "=r" (value));

	return !(value & (1 << 16));
}

static struct kobject *kobject;

static ssize_t
csselr_el1_show(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	uint64_t value;

	asm volatile("mrs %0, csselr_el1" : "=r" (value));

	return sprintf(buf, "%llx\n", value);
}

static ssize_t
csselr_el1_store(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	const char *buf,
	size_t count)
{
	uint64_t value;

	sscanf(buf, "%llx", &value);

	asm volatile(
		"msr csselr_el1, %0\n\t"
		"isb\n\t"
		:: "r" (value));

	return count;
}

static struct kobj_attribute cpuregs_csselr_el1 = __ATTR_RW(csselr_el1);

static ssize_t
ccsidr_el1_show(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	uint64_t value;

	asm volatile("mrs %0, ccsidr_el1" : "=r" (value));

	return sprintf(buf, "%llx\n", value);
}

static struct kobj_attribute cpuregs_ccsidr_el1 = __ATTR_RO(ccsidr_el1);

static ssize_t
pmcr0_el1_show(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	uint64_t value;

	asm volatile("mrs %0, S3_1_c15_c0_0" : "=r" (value));

	return sprintf(buf, "%llx\n", value);
}

static ssize_t
pmcr0_el1_store(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	const char *buf,
	size_t count)
{
	uint64_t value;

	sscanf(buf, "%llx", &value);

	asm volatile(
		"msr S3_1_c15_c0_0, %0\n\t"
		"isb\n\t"
		:: "r" (value));

	return count;
}

static struct kobj_attribute cpuregs_pmcr0_el1 = __ATTR_RW(pmcr0_el1);

static ssize_t
clidr_el1_show(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	uint64_t value;

	asm volatile("mrs %0, clidr_el1" : "=r" (value));

	return sprintf(buf, "%llx\n", value);
}

static struct kobj_attribute cpuregs_clidr_el1 = __ATTR_RO(clidr_el1);

static ssize_t
sys_apl_hid4_show(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	char *buf)
{
	uint64_t value;

	if (is_ecore()) {
		asm volatile("mrs %0, S3_0_c15_c4_1" : "=r" (value));
	} else {
		asm volatile("mrs %0, S3_0_c15_c4_0" : "=r" (value));
	}

	return sprintf(buf, "%llx\n", value);
}

static ssize_t
sys_apl_hid4_store(
	struct kobject *kobj,
	struct kobj_attribute *attr,
	const char *buf,
	size_t count)
{
	uint64_t value;

	sscanf(buf, "%llx", &value);

	if (is_ecore()) {
		asm volatile(
			"msr S3_0_c15_c4_1, %0\n\t"
			"isb\n\t"
			:: "r" (value));
	} else {
		asm volatile(
			"msr S3_0_c15_c4_0, %0\n\t"
			"isb\n\t"
			:: "r" (value));
	}

	return count;
}

static struct kobj_attribute cpuregs_sys_apl_hid4 = __ATTR_RW(sys_apl_hid4);

static struct attribute *cpuregs_attrs[] = {
	&cpuregs_csselr_el1.attr,
	&cpuregs_ccsidr_el1.attr,
	&cpuregs_pmcr0_el1.attr,
	&cpuregs_clidr_el1.attr,
	&cpuregs_sys_apl_hid4.attr,
	NULL,
};

static struct attribute_group cpuregs_attr_group = {
	.attrs = cpuregs_attrs,
	.name = "regs",
};

int
sysregs_init(void)
{
	int rc;

	kobject = kobject_create_and_add("apple", kernel_kobj);

	if (!kobject) {
		printk(KERN_INFO "kmod: could not create kobject.\n");
		return -ENOMEM;
	}

	rc = sysfs_create_group(kobject, &cpuregs_attr_group);

	if (rc) {
		printk(KERN_INFO "kmod: ould not create sysfs group.\n");
		kobject_put(kobject);

		return rc;
	}

	return 0;
}

void
sysregs_exit(void)
{
	if (kobject) {
		sysfs_remove_group(kobject, &cpuregs_attr_group);
		kobject_put(kobject);
	}
}
