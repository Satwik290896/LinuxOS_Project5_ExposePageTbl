#include <linux/syscalls.h>
#include <linux/expose_pgtbl.h>

/*
 * Investigate the page table layout.
 *
 * The page table layout varies over different architectures (eg. x86 vs arm).
 * It also changes with the change of system configuration.  
 *
 * You need to implement a system call to get the page table layout information
 * of the current system. Use syscall number 441.
 * @pgtbl_info : user address to store the related infomation; note the
 * normal page size can be inferred from the page_shift.
 */
SYSCALL_DEFINE1(get_pagetable_layout, struct pagetable_layout_info __user *, pgtbl_info)
{
	// if(!pgtbl_info)
	// 	return -EINVAL;
	struct pagetable_layout_info tmp;
	tmp.pgdir_shift = PGDIR_SHIFT;
	tmp.p4d_shift = P4D_SHIFT;
	tmp.pud_shift = PUD_SHIFT;
	tmp.pmd_shift = PMD_SHIFT;
	tmp.page_shift = PAGE_SHIFT;
	if(copy_to_user(pgtbl_info, &tmp, sizeof(struct pagetable_layout_info)))
		return -EFAULT;
	return 0;
}

SYSCALL_DEFINE2(expose_page_table, pid_t, pid, struct expose_pgtbl_args __user *, args)
{
	return 0;
}

SYSCALL_DEFINE1(get_pa_contents, long, phys_addr)
{
	/* This may need to be tested and revised after 442 is done for further testing */
	return *((int *)phys_to_virt(phys_addr));
}
